//go:build darwin && !ios && !iossimulator
// +build darwin,!ios,!iossimulator

package ieproxy

import (
	"fmt"
	"net/url"
	"runtime"
	"sync"
	"unsafe"

	"github.com/ebitengine/purego"
)

var (
	// Additional CF functions needed for PAC
	pCFStringCreateWithCString                 func(uintptr, *byte, uint32) uintptr
	pCFURLCreateWithString                     func(uintptr, uintptr, uintptr) uintptr
	pCFGetTypeID                               func(uintptr) uint64
	pCFArrayGetTypeID                          func() uint64
	pCFEqual                                   func(uintptr, uintptr) bool
	pCFRetain                                  func(uintptr) uintptr
	pCFRunLoopGetCurrent                       func() uintptr
	pCFRunLoopAddSource                        func(uintptr, uintptr, uintptr)
	pCFRunLoopRunInMode                        func(uintptr, float64, bool) int32
	pCFRunLoopRemoveSource                     func(uintptr, uintptr, uintptr)
	pCFRunLoopStop                             func(uintptr)
	pCFNetworkExecuteProxyAutoConfigurationURL func(uintptr, uintptr, uintptr, uintptr) uintptr

	// Constants for PAC
	pkCFProxyTypeKey       uintptr
	pkCFProxyTypeNone      uintptr
	pkCFProxyTypeHTTP      uintptr
	pkCFProxyTypeHTTPS     uintptr
	pkCFProxyHostNameKey   uintptr
	pkCFProxyPortNumberKey uintptr

	// Private run loop mode string (created once)
	goIEProxyRunLoopMode uintptr

	// Callback trampoline for CFNetworkExecuteProxyAutoConfigurationURL (created once at init).
	pacCallback uintptr
)

type cfStreamClientContext struct {
	version         int64
	info            uintptr
	retain          uintptr
	release         uintptr
	copyDescription uintptr
}

func initPACLibraries() {
	// CoreFoundation functions
	purego.RegisterLibFunc(&pCFStringCreateWithCString, libCoreFoundation, "CFStringCreateWithCString")
	purego.RegisterLibFunc(&pCFURLCreateWithString, libCoreFoundation, "CFURLCreateWithString")
	purego.RegisterLibFunc(&pCFGetTypeID, libCoreFoundation, "CFGetTypeID")
	purego.RegisterLibFunc(&pCFArrayGetTypeID, libCoreFoundation, "CFArrayGetTypeID")
	purego.RegisterLibFunc(&pCFEqual, libCoreFoundation, "CFEqual")
	purego.RegisterLibFunc(&pCFRetain, libCoreFoundation, "CFRetain")
	purego.RegisterLibFunc(&pCFRunLoopGetCurrent, libCoreFoundation, "CFRunLoopGetCurrent")
	purego.RegisterLibFunc(&pCFRunLoopAddSource, libCoreFoundation, "CFRunLoopAddSource")
	purego.RegisterLibFunc(&pCFRunLoopRunInMode, libCoreFoundation, "CFRunLoopRunInMode")
	purego.RegisterLibFunc(&pCFRunLoopRemoveSource, libCoreFoundation, "CFRunLoopRemoveSource")
	purego.RegisterLibFunc(&pCFRunLoopStop, libCoreFoundation, "CFRunLoopStop")
	purego.RegisterLibFunc(&pCFNetworkExecuteProxyAutoConfigurationURL, libCFNetwork, "CFNetworkExecuteProxyAutoConfigurationURL")

	pkCFProxyTypeKey = loadCFStringConst(libCFNetwork, "kCFProxyTypeKey")
	pkCFProxyTypeNone = loadCFStringConst(libCFNetwork, "kCFProxyTypeNone")
	pkCFProxyTypeHTTP = loadCFStringConst(libCFNetwork, "kCFProxyTypeHTTP")
	pkCFProxyTypeHTTPS = loadCFStringConst(libCFNetwork, "kCFProxyTypeHTTPS")
	pkCFProxyHostNameKey = loadCFStringConst(libCFNetwork, "kCFProxyHostNameKey")
	pkCFProxyPortNumberKey = loadCFStringConst(libCFNetwork, "kCFProxyPortNumberKey")

	modeBytes := []byte("go-ieproxy\x00")
	goIEProxyRunLoopMode = pCFStringCreateWithCString(0, &modeBytes[0], kCFStringEncodingUTF8)

	pacCallback = purego.NewCallback(func(client uintptr, proxies uintptr, cfError uintptr) {
		result := (*uintptr)(unsafe.Pointer(client))
		if cfError != 0 {
			*result = pCFRetain(cfError)
		} else {
			*result = pCFRetain(proxies)
		}
		pCFRunLoopStop(pCFRunLoopGetCurrent())
	})
}

var pacLibsInitOnce sync.Once

func ensurePACLibs() {
	ensureLibs()
	pacLibsInitOnce.Do(initPACLibraries)
}

// executePACLookup calls CFNetworkExecuteProxyAutoConfigurationURL on the
// calling goroutine's OS thread. LockOSThread ensures that CFRunLoopGetCurrent
// returns the same run loop for both the setup calls and the callback.
func executePACLookup(pacUrl, reqUrl uintptr) uintptr {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	var cfResult uintptr
	ctx := cfStreamClientContext{
		version: 0,
		info:    uintptr(unsafe.Pointer(&cfResult)),
	}

	rl := pCFRunLoopGetCurrent()
	runLoopSrc := pCFNetworkExecuteProxyAutoConfigurationURL(
		pacUrl, reqUrl, pacCallback, uintptr(unsafe.Pointer(&ctx)),
	)
	if runLoopSrc == 0 {
		return 0
	}

	pCFRunLoopAddSource(rl, runLoopSrc, goIEProxyRunLoopMode)
	pCFRunLoopRunInMode(goIEProxyRunLoopMode, 1e308 /* DBL_MAX */, false)
	pCFRunLoopRemoveSource(rl, runLoopSrc, goIEProxyRunLoopMode)
	pCFRelease(runLoopSrc)

	return cfResult
}

func (psc *ProxyScriptConf) findProxyForURL(URL string) string {
	if !psc.Active {
		return ""
	}
	proxy := getProxyForURL(psc.PreConfiguredURL, URL)
	return proxy
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
	pacUrl := pCFURLCreateWithString(0, pacStr, 0)
	reqUrl := pCFURLCreateWithString(0, reqStr, 0)
	defer func() {
		pCFRelease(pacStr)
		pCFRelease(reqStr)
		if pacUrl != 0 {
			pCFRelease(pacUrl)
		}
		if reqUrl != 0 {
			pCFRelease(reqUrl)
		}
	}()

	if pacUrl == 0 || reqUrl == 0 {
		return ""
	}

	result := executePACLookup(pacUrl, reqUrl)

	if result == 0 {
		return ""
	}
	defer pCFRelease(result)

	if pCFGetTypeID(result) != pCFArrayGetTypeID() {
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
	if pxyType == 0 {
		return ""
	}

	if pCFEqual(pxyType, pkCFProxyTypeNone) {
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
