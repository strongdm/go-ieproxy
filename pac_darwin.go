//go:build darwin && !ios && !iossimulator
// +build darwin,!ios,!iossimulator

package ieproxy

// This file is a Go port of Chromium's net/proxy_resolution/proxy_resolver_apple.cc.
// The upstream implementation is the canonical reference for correctly driving
// CFNetworkExecuteProxyAutoConfigurationURL from a synchronous caller.
//
// Two pieces of the Chromium implementation are load-bearing and were missing
// from earlier revisions of this file:
//
//  1. A dummy CFNetworkCopyProxiesForURL call prior to
//     CFNetworkExecuteProxyAutoConfigurationURL. This is a workaround for
//     rdar://problem/5530166 — without it, the first PAC lookup on a thread
//     can return an empty/incomplete proxy list.
//
//  2. A process-wide lock plus a CFRunLoopObserver that serializes the
//     add-source / result-callback / remove-source events across concurrent
//     PAC lookups. CFNetworkExecuteProxyAutoConfigurationURL's internal
//     machinery is not safe to drive concurrently from multiple threads at
//     the event level, even though separate run loops are used.

import (
	"fmt"
	"net/url"
	"runtime"
	"sync"
	"unsafe"

	"github.com/ebitengine/purego"
)

var (
	// CoreFoundation
	pCFStringCreateWithCString func(uintptr, *byte, uint32) uintptr
	pCFURLCreateWithString     func(uintptr, uintptr, uintptr) uintptr
	pCFGetTypeID               func(uintptr) uint64
	pCFArrayGetTypeID          func() uint64
	pCFErrorGetTypeID          func() uint64
	pCFEqual                   func(uintptr, uintptr) bool
	pCFRetain                  func(uintptr) uintptr
	pCFDictionaryCreate        func(uintptr, *uintptr, *uintptr, int64, uintptr, uintptr) uintptr

	// CFRunLoop
	pCFRunLoopGetCurrent      func() uintptr
	pCFRunLoopAddSource       func(uintptr, uintptr, uintptr)
	pCFRunLoopRemoveSource    func(uintptr, uintptr, uintptr)
	pCFRunLoopRunInMode       func(uintptr, float64, bool) int32
	pCFRunLoopStop            func(uintptr)
	pCFRunLoopObserverCreate  func(uintptr, uint64, bool, int64, uintptr, *cfRunLoopObserverContext) uintptr
	pCFRunLoopAddObserver     func(uintptr, uintptr, uintptr)
	pCFRunLoopRemoveObserver  func(uintptr, uintptr, uintptr)

	// CFNetwork
	pCFNetworkExecuteProxyAutoConfigurationURL func(uintptr, uintptr, uintptr, uintptr) uintptr
	pCFNetworkCopyProxiesForURL                func(uintptr, uintptr) uintptr

	// CFProxy key constants (retrieved from CFNetwork)
	pkCFProxyTypeKey       uintptr
	pkCFProxyTypeNone      uintptr
	pkCFProxyTypeHTTP      uintptr
	pkCFProxyTypeHTTPS     uintptr
	pkCFProxyHostNameKey   uintptr
	pkCFProxyPortNumberKey uintptr

	// Private run loop mode used to isolate PAC lookups from any other
	// run loop sources scheduled on the same thread.
	goIEProxyRunLoopMode uintptr

	// Trampoline for the PAC result callback. Created once.
	pacResultCallback uintptr

	// Trampoline for the run loop observer callback. Created once.
	pacObserverCallback uintptr

	// Global lock serializing run loop source events across concurrent
	// CFNetworkExecuteProxyAutoConfigurationURL calls. Mirrors
	// GetCFNetworkPacRunloopLock() in Chromium.
	cfNetworkPacLock sync.Mutex

	// Per-observer state registry. The CFRunLoopObserverContext `info` field
	// must be a plain C pointer, but Go's GC cannot see references held only
	// through a uintptr, and goroutine stacks may move. Instead of passing a
	// Go pointer through CoreFoundation, we key the observer state by the
	// CFRunLoopObserverRef (which is stable for the lifetime of the
	// observer) and look it up from the callback.
	observerStatesMu sync.Mutex
	observerStates   = map[uintptr]*observerState{}

	// Per-lookup result registry. The result callback receives the `info`
	// pointer from CFStreamClientContext as its `client` argument; we pass
	// an opaque integer token and look up the Go-owned result slot here.
	// This avoids shipping a Go pointer through CoreFoundation.
	resultRegistryMu sync.Mutex
	resultRegistry   = map[uintptr]*uintptr{}
	resultNextID     uintptr
)

// CFRunLoopActivity bit flags (CoreFoundation/CFRunLoop.h).
const (
	kCFRunLoopBeforeSources = 1 << 2
	kCFRunLoopBeforeWaiting = 1 << 5
	kCFRunLoopExit          = 1 << 7
)

// CFStreamClientContext — passed as the `info` pointer to
// CFNetworkExecuteProxyAutoConfigurationURL. The `info` field is delivered
// verbatim to the result callback as its `client` argument.
type cfStreamClientContext struct {
	version         int64
	info            uintptr
	retain          uintptr
	release         uintptr
	copyDescription uintptr
}

// CFRunLoopObserverContext — passed to CFRunLoopObserverCreate.
type cfRunLoopObserverContext struct {
	version         int64
	info            uintptr
	retain          uintptr
	release         uintptr
	copyDescription uintptr
}

// observerState tracks whether a given run loop observer has currently
// acquired cfNetworkPacLock. Looked up from observerStates by the observer
// ref delivered to the callback.
type observerState struct {
	lockAcquired bool
}

func initPACLibraries() {
	purego.RegisterLibFunc(&pCFStringCreateWithCString, libCoreFoundation, "CFStringCreateWithCString")
	purego.RegisterLibFunc(&pCFURLCreateWithString, libCoreFoundation, "CFURLCreateWithString")
	purego.RegisterLibFunc(&pCFGetTypeID, libCoreFoundation, "CFGetTypeID")
	purego.RegisterLibFunc(&pCFArrayGetTypeID, libCoreFoundation, "CFArrayGetTypeID")
	purego.RegisterLibFunc(&pCFErrorGetTypeID, libCoreFoundation, "CFErrorGetTypeID")
	purego.RegisterLibFunc(&pCFEqual, libCoreFoundation, "CFEqual")
	purego.RegisterLibFunc(&pCFRetain, libCoreFoundation, "CFRetain")
	purego.RegisterLibFunc(&pCFDictionaryCreate, libCoreFoundation, "CFDictionaryCreate")

	purego.RegisterLibFunc(&pCFRunLoopGetCurrent, libCoreFoundation, "CFRunLoopGetCurrent")
	purego.RegisterLibFunc(&pCFRunLoopAddSource, libCoreFoundation, "CFRunLoopAddSource")
	purego.RegisterLibFunc(&pCFRunLoopRemoveSource, libCoreFoundation, "CFRunLoopRemoveSource")
	purego.RegisterLibFunc(&pCFRunLoopRunInMode, libCoreFoundation, "CFRunLoopRunInMode")
	purego.RegisterLibFunc(&pCFRunLoopStop, libCoreFoundation, "CFRunLoopStop")
	purego.RegisterLibFunc(&pCFRunLoopObserverCreate, libCoreFoundation, "CFRunLoopObserverCreate")
	purego.RegisterLibFunc(&pCFRunLoopAddObserver, libCoreFoundation, "CFRunLoopAddObserver")
	purego.RegisterLibFunc(&pCFRunLoopRemoveObserver, libCoreFoundation, "CFRunLoopRemoveObserver")

	purego.RegisterLibFunc(&pCFNetworkExecuteProxyAutoConfigurationURL, libCFNetwork, "CFNetworkExecuteProxyAutoConfigurationURL")
	purego.RegisterLibFunc(&pCFNetworkCopyProxiesForURL, libCFNetwork, "CFNetworkCopyProxiesForURL")

	pkCFProxyTypeKey = loadCFStringConst(libCFNetwork, "kCFProxyTypeKey")
	pkCFProxyTypeNone = loadCFStringConst(libCFNetwork, "kCFProxyTypeNone")
	pkCFProxyTypeHTTP = loadCFStringConst(libCFNetwork, "kCFProxyTypeHTTP")
	pkCFProxyTypeHTTPS = loadCFStringConst(libCFNetwork, "kCFProxyTypeHTTPS")
	pkCFProxyHostNameKey = loadCFStringConst(libCFNetwork, "kCFProxyHostNameKey")
	pkCFProxyPortNumberKey = loadCFStringConst(libCFNetwork, "kCFProxyPortNumberKey")

	modeBytes := []byte("com.strongdm.go-ieproxy\x00")
	goIEProxyRunLoopMode = pCFStringCreateWithCString(0, &modeBytes[0], kCFStringEncodingUTF8)

	// Result callback: signature matches
	// void (*CFProxyAutoConfigurationResultCallback)(void *client,
	//                                                CFArrayRef proxyList,
	//                                                CFErrorRef error);
	//
	// `client` is an opaque token registered in resultRegistry, not a Go
	// pointer — same rationale as the observer registry above.
	pacResultCallback = purego.NewCallback(func(client uintptr, proxies uintptr, cfError uintptr) {
		resultRegistryMu.Lock()
		slot, ok := resultRegistry[client]
		resultRegistryMu.Unlock()
		if ok {
			if cfError != 0 {
				*slot = pCFRetain(cfError)
			} else if proxies != 0 {
				*slot = pCFRetain(proxies)
			}
		}
		pCFRunLoopStop(pCFRunLoopGetCurrent())
	})

	// Observer callback: signature matches
	// void (*CFRunLoopObserverCallBack)(CFRunLoopObserverRef observer,
	//                                   CFRunLoopActivity activity,
	//                                   void *info);
	//
	// The observer ref is used as the registry key because passing a Go
	// pointer through the `info` field is unsafe under Go's GC.
	pacObserverCallback = purego.NewCallback(func(observer uintptr, activity uint64, info uintptr) {
		observerStatesMu.Lock()
		state, ok := observerStates[observer]
		observerStatesMu.Unlock()
		if !ok {
			return
		}
		switch activity {
		case kCFRunLoopBeforeSources:
			if !state.lockAcquired {
				cfNetworkPacLock.Lock()
				state.lockAcquired = true
			}
		case kCFRunLoopBeforeWaiting, kCFRunLoopExit:
			if state.lockAcquired {
				state.lockAcquired = false
				cfNetworkPacLock.Unlock()
			}
		}
	})
}

var pacLibsInitOnce sync.Once

func ensurePACLibs() {
	ensureLibs()
	pacLibsInitOnce.Do(initPACLibraries)
}

// executePACLookup performs a synchronous CFNetworkExecuteProxyAutoConfigurationURL
// call, returning a retained CFArrayRef of proxies (or CFErrorRef), or 0 on failure.
//
// The implementation mirrors ProxyResolverApple::GetProxyForURL in Chromium:
//
//  1. Issue a dummy CFNetworkCopyProxiesForURL to prime CFNetwork
//     (rdar://problem/5530166).
//  2. Schedule the async PAC run loop source.
//  3. Install a CFRunLoopObserver that acquires a global lock during source
//     firing, serializing callback execution across threads.
//  4. Add source + run + remove source, with the add/remove bracketed by the
//     lock (as in Chromium).
func executePACLookup(pacUrl, reqUrl uintptr) uintptr {
	// CFRunLoopGetCurrent must return the same run loop for the add/run/remove
	// sequence, so pin this goroutine to its OS thread for the duration.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	// Step 1: prime CFNetwork. The result is discarded; we only care about the
	// side-effect of initializing internal state.
	emptyDict := pCFDictionaryCreate(0, nil, nil, 0, 0, 0)
	if emptyDict != 0 {
		if dummy := pCFNetworkCopyProxiesForURL(reqUrl, emptyDict); dummy != 0 {
			pCFRelease(dummy)
		}
		pCFRelease(emptyDict)
	}

	// Step 2: schedule async PAC resolution.
	//
	// Register a result slot under an opaque token. The token — not a Go
	// pointer — is passed via CFStreamClientContext.info and resurfaces in
	// the result callback's `client` argument.
	resultSlot := new(uintptr)
	resultRegistryMu.Lock()
	resultNextID++
	resultToken := resultNextID
	resultRegistry[resultToken] = resultSlot
	resultRegistryMu.Unlock()
	defer func() {
		resultRegistryMu.Lock()
		delete(resultRegistry, resultToken)
		resultRegistryMu.Unlock()
	}()

	ctx := cfStreamClientContext{
		version: 0,
		info:    resultToken,
	}
	runLoopSrc := pCFNetworkExecuteProxyAutoConfigurationURL(
		pacUrl, reqUrl, pacResultCallback, uintptr(unsafe.Pointer(&ctx)),
	)
	if runLoopSrc == 0 {
		return 0
	}
	// CFNetworkExecuteProxyAutoConfigurationURL returns a source that the
	// caller owns and must release despite the "Copy" absent from its name.
	defer pCFRelease(runLoopSrc)

	// Step 3: install the run loop observer that serializes source events.
	// Observer context is zeroed — state is stored in observerStates keyed
	// by the observer ref, not passed through info.
	var obsCtx cfRunLoopObserverContext
	observer := pCFRunLoopObserverCreate(
		0, // kCFAllocatorDefault
		kCFRunLoopBeforeSources|kCFRunLoopBeforeWaiting|kCFRunLoopExit,
		true, // repeats
		0,    // order
		pacObserverCallback,
		&obsCtx,
	)
	if observer == 0 {
		return 0
	}
	defer pCFRelease(observer)

	state := &observerState{}
	observerStatesMu.Lock()
	observerStates[observer] = state
	observerStatesMu.Unlock()
	defer func() {
		observerStatesMu.Lock()
		delete(observerStates, observer)
		observerStatesMu.Unlock()
	}()

	rl := pCFRunLoopGetCurrent()
	pCFRunLoopAddObserver(rl, observer, goIEProxyRunLoopMode)
	defer pCFRunLoopRemoveObserver(rl, observer, goIEProxyRunLoopMode)

	// Step 4: add source (under lock), run, remove source (under lock).
	cfNetworkPacLock.Lock()
	pCFRunLoopAddSource(rl, runLoopSrc, goIEProxyRunLoopMode)
	cfNetworkPacLock.Unlock()

	// DBL_MAX timeout with returnAfterSourceHandled=false matches Chromium.
	// The loop exits when the callback invokes CFRunLoopStop, or if the mode
	// drains (kCFRunLoopRunFinished / kCFRunLoopRunStopped).
	pCFRunLoopRunInMode(goIEProxyRunLoopMode, 1e308, false)

	cfNetworkPacLock.Lock()
	pCFRunLoopRemoveSource(rl, runLoopSrc, goIEProxyRunLoopMode)
	cfNetworkPacLock.Unlock()

	// Defensive: if the run loop exited via a path that skipped
	// kCFRunLoopBeforeWaiting/Exit, the observer may still hold the lock.
	if state.lockAcquired {
		state.lockAcquired = false
		cfNetworkPacLock.Unlock()
	}

	return *resultSlot
}

func (psc *ProxyScriptConf) findProxyForURL(URL string) string {
	if !psc.Active {
		return ""
	}
	return getProxyForURL(psc.PreConfiguredURL, URL)
}

func getProxyForURL(pacFileURL, targetURL string) string {
	if pacFileURL == "" {
		pacFileURL = getPacUrl()
	}
	if pacFileURL == "" {
		return ""
	}
	if u, err := url.Parse(pacFileURL); err != nil || u.Scheme == "" {
		return ""
	}

	ensurePACLibs()

	pacBytes := []byte(pacFileURL + "\x00")
	reqBytes := []byte(targetURL + "\x00")

	pacStr := pCFStringCreateWithCString(0, &pacBytes[0], kCFStringEncodingUTF8)
	reqStr := pCFStringCreateWithCString(0, &reqBytes[0], kCFStringEncodingUTF8)
	if pacStr == 0 || reqStr == 0 {
		if pacStr != 0 {
			pCFRelease(pacStr)
		}
		if reqStr != 0 {
			pCFRelease(reqStr)
		}
		return ""
	}
	defer pCFRelease(pacStr)
	defer pCFRelease(reqStr)

	pacUrl := pCFURLCreateWithString(0, pacStr, 0)
	if pacUrl == 0 {
		return ""
	}
	defer pCFRelease(pacUrl)

	reqUrl := pCFURLCreateWithString(0, reqStr, 0)
	if reqUrl == 0 {
		return ""
	}
	defer pCFRelease(reqUrl)

	result := executePACLookup(pacUrl, reqUrl)
	if result == 0 {
		return ""
	}
	defer pCFRelease(result)

	// The callback delivers either a CFArrayRef of proxy dictionaries or a
	// CFErrorRef. Anything else is unexpected.
	typeID := pCFGetTypeID(result)
	if typeID == pCFErrorGetTypeID() {
		return ""
	}
	if typeID != pCFArrayGetTypeID() {
		return ""
	}

	if pCFArrayGetCount(result) == 0 {
		return ""
	}

	pxy := pCFArrayGetValueAtIndex(result, 0)
	if pxy == 0 {
		return ""
	}

	pxyType := pCFDictionaryGetValue(pxy, pkCFProxyTypeKey)
	if pxyType == 0 || pCFEqual(pxyType, pkCFProxyTypeNone) {
		return ""
	}

	if pCFEqual(pxyType, pkCFProxyTypeHTTP) || pCFEqual(pxyType, pkCFProxyTypeHTTPS) {
		host := pCFDictionaryGetValue(pxy, pkCFProxyHostNameKey)
		port := pCFDictionaryGetValue(pxy, pkCFProxyPortNumberKey)
		hostStr := cfStringToGoString(host)
		portInt := 80
		if pCFEqual(pxyType, pkCFProxyTypeHTTPS) {
			portInt = 443
		}
		if port != 0 {
			portInt = cfNumberGetInt(port)
		}
		return fmt.Sprintf("%s:%d", hostStr, portInt)
	}

	return ""
}

func getPacUrl() string {
	ensurePACLibs()

	cfDictProxy := pCFNetworkCopySystemProxySettings()
	if cfDictProxy == 0 {
		return ""
	}
	defer pCFRelease(cfDictProxy)

	pacEnable := pCFDictionaryGetValue(cfDictProxy, pkCFNetworkProxiesProxyAutoConfigEnable)
	if pacEnable == 0 || cfNumberGetInt(pacEnable) == 0 {
		return ""
	}

	pacUrlStr := pCFDictionaryGetValue(cfDictProxy, pkCFNetworkProxiesProxyAutoConfigURLString)
	if pacUrlStr == 0 {
		return ""
	}
	return cfStringToGoString(pacUrlStr)
}
