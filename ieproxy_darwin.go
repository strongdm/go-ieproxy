//go:build darwin && !ios && !iossimulator
// +build darwin,!ios,!iossimulator

package ieproxy

import (
	"fmt"
	"strings"
	"sync"
	"unsafe"

	"github.com/ebitengine/purego"
)

var once sync.Once
var darwinProxyConf ProxyConf

var (
	libCoreFoundation uintptr
	libCFNetwork      uintptr

	// CoreFoundation functions
	pCFRelease                          func(uintptr)
	pCFDictionaryGetValue               func(uintptr, uintptr) uintptr
	pCFNumberGetValue                   func(uintptr, int32, unsafe.Pointer) bool
	pCFStringGetCString                 func(uintptr, *byte, int64, uint32) bool
	pCFStringGetLength                  func(uintptr) int64
	pCFStringGetMaximumSizeForEncoding  func(int64, uint32) int64
	pCFArrayGetCount                    func(uintptr) int64
	pCFArrayGetValueAtIndex             func(uintptr, int64) uintptr

	// CFNetwork functions
	pCFNetworkCopySystemProxySettings func() uintptr

	// CF string key constants (retrieved as pointer-to-pointer from dylib)
	pkCFNetworkProxiesHTTPEnable               uintptr
	pkCFNetworkProxiesHTTPProxy                uintptr
	pkCFNetworkProxiesHTTPPort                 uintptr
	pkCFNetworkProxiesHTTPSEnable              uintptr
	pkCFNetworkProxiesHTTPSProxy               uintptr
	pkCFNetworkProxiesHTTPSPort                uintptr
	pkCFNetworkProxiesExceptionsList           uintptr
	pkCFNetworkProxiesProxyAutoConfigEnable    uintptr
	pkCFNetworkProxiesProxyAutoConfigURLString uintptr
)

const kCFStringEncodingUTF8 = 0x08000100
const kCFNumberIntType = 9

func initLibraries() {
	var err error
	libCoreFoundation, err = purego.Dlopen("/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation", purego.RTLD_LAZY|purego.RTLD_GLOBAL)
	if err != nil {
		panic("ieproxy: failed to load CoreFoundation: " + err.Error())
	}
	libCFNetwork, err = purego.Dlopen("/System/Library/Frameworks/CFNetwork.framework/CFNetwork", purego.RTLD_LAZY|purego.RTLD_GLOBAL)
	if err != nil {
		panic("ieproxy: failed to load CFNetwork: " + err.Error())
	}

	purego.RegisterLibFunc(&pCFRelease, libCoreFoundation, "CFRelease")
	purego.RegisterLibFunc(&pCFDictionaryGetValue, libCoreFoundation, "CFDictionaryGetValue")
	purego.RegisterLibFunc(&pCFNumberGetValue, libCoreFoundation, "CFNumberGetValue")
	purego.RegisterLibFunc(&pCFStringGetCString, libCoreFoundation, "CFStringGetCString")
	purego.RegisterLibFunc(&pCFStringGetLength, libCoreFoundation, "CFStringGetLength")
	purego.RegisterLibFunc(&pCFStringGetMaximumSizeForEncoding, libCoreFoundation, "CFStringGetMaximumSizeForEncoding")
	purego.RegisterLibFunc(&pCFArrayGetCount, libCoreFoundation, "CFArrayGetCount")
	purego.RegisterLibFunc(&pCFArrayGetValueAtIndex, libCoreFoundation, "CFArrayGetValueAtIndex")
	purego.RegisterLibFunc(&pCFNetworkCopySystemProxySettings, libCFNetwork, "CFNetworkCopySystemProxySettings")

	pkCFNetworkProxiesHTTPEnable = loadCFStringConst(libCFNetwork, "kCFNetworkProxiesHTTPEnable")
	pkCFNetworkProxiesHTTPProxy = loadCFStringConst(libCFNetwork, "kCFNetworkProxiesHTTPProxy")
	pkCFNetworkProxiesHTTPPort = loadCFStringConst(libCFNetwork, "kCFNetworkProxiesHTTPPort")
	pkCFNetworkProxiesHTTPSEnable = loadCFStringConst(libCFNetwork, "kCFNetworkProxiesHTTPSEnable")
	pkCFNetworkProxiesHTTPSProxy = loadCFStringConst(libCFNetwork, "kCFNetworkProxiesHTTPSProxy")
	pkCFNetworkProxiesHTTPSPort = loadCFStringConst(libCFNetwork, "kCFNetworkProxiesHTTPSPort")
	pkCFNetworkProxiesExceptionsList = loadCFStringConst(libCFNetwork, "kCFNetworkProxiesExceptionsList")
	pkCFNetworkProxiesProxyAutoConfigEnable = loadCFStringConst(libCFNetwork, "kCFNetworkProxiesProxyAutoConfigEnable")
	pkCFNetworkProxiesProxyAutoConfigURLString = loadCFStringConst(libCFNetwork, "kCFNetworkProxiesProxyAutoConfigURLString")
}

// loadCFStringConst returns the CFStringRef stored at the exported symbol (a pointer to a CFStringRef).
func loadCFStringConst(lib uintptr, name string) uintptr {
	sym, err := purego.Dlsym(lib, name)
	if err != nil {
		panic("ieproxy: symbol not found: " + name + ": " + err.Error())
	}
	// sym is the address of the global variable (a CFStringRef*). Dereference once.
	return *(*uintptr)(unsafe.Pointer(sym))
}

func cfStringToGoString(cfStr uintptr) string {
	if cfStr == 0 {
		return ""
	}
	// Size the buffer to fit any UTF-8 encoding of this CFString, plus one
	// byte for the trailing NUL that CFStringGetCString always writes.
	maxSize := pCFStringGetMaximumSizeForEncoding(pCFStringGetLength(cfStr), kCFStringEncodingUTF8)
	if maxSize <= 0 {
		return ""
	}
	buf := make([]byte, maxSize+1)
	if !pCFStringGetCString(cfStr, &buf[0], int64(len(buf)), kCFStringEncodingUTF8) {
		return ""
	}
	end := 0
	for end < len(buf) && buf[end] != 0 {
		end++
	}
	return string(buf[:end])
}

func cfNumberGetInt(cfNum uintptr) int {
	if cfNum == 0 {
		return 0
	}
	var val int32
	pCFNumberGetValue(cfNum, kCFNumberIntType, unsafe.Pointer(&val))
	return int(val)
}

func cfArrayGetStrings(cfArray uintptr) []string {
	if cfArray == 0 {
		return nil
	}
	count := pCFArrayGetCount(cfArray)
	result := make([]string, 0, count)
	for i := int64(0); i < count; i++ {
		elem := pCFArrayGetValueAtIndex(cfArray, i)
		if elem != 0 {
			result = append(result, cfStringToGoString(elem))
		}
	}
	return result
}

var libsOnce sync.Once

func ensureLibs() {
	libsOnce.Do(initLibraries)
}

// GetConf retrieves the proxy configuration from the macOS System Settings.
func getConf() ProxyConf {
	once.Do(writeConf)
	return darwinProxyConf
}

// reloadConf forces a reload of the proxy configuration.
func reloadConf() ProxyConf {
	writeConf()
	return getConf()
}

func writeConf() {
	ensureLibs()

	cfDictProxy := pCFNetworkCopySystemProxySettings()
	if cfDictProxy == 0 {
		return
	}
	defer pCFRelease(cfDictProxy)

	darwinProxyConf = ProxyConf{}

	cfNumHttpEnable := pCFDictionaryGetValue(cfDictProxy, pkCFNetworkProxiesHTTPEnable)
	if cfNumHttpEnable != 0 && cfNumberGetInt(cfNumHttpEnable) > 0 {
		darwinProxyConf.Static.Active = true
		if darwinProxyConf.Static.Protocols == nil {
			darwinProxyConf.Static.Protocols = make(map[string]string)
		}
		httpHost := pCFDictionaryGetValue(cfDictProxy, pkCFNetworkProxiesHTTPProxy)
		httpPort := pCFDictionaryGetValue(cfDictProxy, pkCFNetworkProxiesHTTPPort)
		darwinProxyConf.Static.Protocols["http"] = fmt.Sprintf("%s:%d", cfStringToGoString(httpHost), cfNumberGetInt(httpPort))
	}

	cfNumHttpsEnable := pCFDictionaryGetValue(cfDictProxy, pkCFNetworkProxiesHTTPSEnable)
	if cfNumHttpsEnable != 0 && cfNumberGetInt(cfNumHttpsEnable) > 0 {
		darwinProxyConf.Static.Active = true
		if darwinProxyConf.Static.Protocols == nil {
			darwinProxyConf.Static.Protocols = make(map[string]string)
		}
		httpsHost := pCFDictionaryGetValue(cfDictProxy, pkCFNetworkProxiesHTTPSProxy)
		httpsPort := pCFDictionaryGetValue(cfDictProxy, pkCFNetworkProxiesHTTPSPort)
		darwinProxyConf.Static.Protocols["https"] = fmt.Sprintf("%s:%d", cfStringToGoString(httpsHost), cfNumberGetInt(httpsPort))
	}

	if darwinProxyConf.Static.Active {
		cfArrayExceptions := pCFDictionaryGetValue(cfDictProxy, pkCFNetworkProxiesExceptionsList)
		if cfArrayExceptions != 0 {
			darwinProxyConf.Static.NoProxy = strings.Join(cfArrayGetStrings(cfArrayExceptions), ",")
		}
	}

	cfNumPacEnable := pCFDictionaryGetValue(cfDictProxy, pkCFNetworkProxiesProxyAutoConfigEnable)
	if cfNumPacEnable != 0 && cfNumberGetInt(cfNumPacEnable) > 0 {
		cfStringPac := pCFDictionaryGetValue(cfDictProxy, pkCFNetworkProxiesProxyAutoConfigURLString)
		if cfStringPac != 0 {
			darwinProxyConf.Automatic.PreConfiguredURL = cfStringToGoString(cfStringPac)
			darwinProxyConf.Automatic.Active = true
		}
	}
}

// OverrideEnvWithStaticProxy writes new values to the
// http_proxy, https_proxy and no_proxy environment variables.
// The values are taken from the macOS System Settings.
func overrideEnvWithStaticProxy(conf ProxyConf, setenv envSetter) {
	if conf.Static.Active {
		for _, scheme := range []string{"http", "https"} {
			url := conf.Static.Protocols[scheme]
			if url != "" {
				setenv(scheme+"_proxy", url)
			}
		}
		if conf.Static.NoProxy != "" {
			setenv("no_proxy", conf.Static.NoProxy)
		}
	}
}
