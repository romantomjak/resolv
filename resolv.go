// +build darwin

package resolv

/*
#cgo LDFLAGS: -framework CoreFoundation -framework SystemConfiguration
#include <CoreFoundation/CoreFoundation.h>
#include <SystemConfiguration/SCDynamicStore.h>
*/
import "C"

import (
	"errors"
	"fmt"
	"math"
	"net"
	"unicode/utf8"
	"unsafe"
)

// StringToCFString returns a CFStringRef.
//
// The CFStringRef type refers to a CFString object, which "encapsulates"
// a Unicode string along with its length.
//
// It is callers responsibility to release the memory using Release()
func StringToCFString(s string) (C.CFStringRef, error) {
	if !utf8.ValidString(s) {
		return 0, errors.New("invalid UTF-8 string")
	}
	if uint64(len(s)) > math.MaxUint32 {
		return 0, errors.New("string is too big")
	}

	bytes := []byte(s)
	var p *C.UInt8
	if len(bytes) > 0 {
		p = (*C.UInt8)(&bytes[0])
	}
	return C.CFStringCreateWithBytes(C.kCFAllocatorDefault, p, C.CFIndex(len(s)), C.kCFStringEncodingUTF8, C.false), nil
}

// Release releases a TypeRef
func Release(ref C.CFTypeRef) {
	if ref != 0 {
		C.CFRelease(ref)
	}
}

// CFDictionaryToPointerMap converts CFDictionaryRef to a map of pointers
func CFDictionaryToPointerMap(ref C.CFDictionaryRef) (m map[C.CFTypeRef]C.CFTypeRef) {
	count := C.CFDictionaryGetCount(ref)
	if count > 0 {
		keys := make([]C.CFTypeRef, count)
		values := make([]C.CFTypeRef, count)
		// keys and values C arrays are parallel to each other. that is, the items
		// at the same indices form a key-value pair from the dictionary
		C.CFDictionaryGetKeysAndValues(ref, (*unsafe.Pointer)(unsafe.Pointer(&keys[0])), (*unsafe.Pointer)(unsafe.Pointer(&values[0])))
		m = make(map[C.CFTypeRef]C.CFTypeRef, count)
		for i := C.CFIndex(0); i < count; i++ {
			m[keys[i]] = values[i]
		}
	}
	return
}

// CFStringToString converts a CFStringRef to a string
func CFStringToString(ref C.CFStringRef) string {
	p := C.CFStringGetCStringPtr(ref, C.kCFStringEncodingUTF8)
	if p != nil {
		return C.GoString(p)
	}
	length := C.CFStringGetLength(ref)
	if length == 0 {
		return ""
	}
	maxBufLen := C.CFStringGetMaximumSizeForEncoding(length, C.kCFStringEncodingUTF8)
	if maxBufLen == 0 {
		return ""
	}
	buf := make([]byte, maxBufLen)
	var usedBufLen C.CFIndex
	_ = C.CFStringGetBytes(ref, C.CFRange{0, length}, C.kCFStringEncodingUTF8, C.UInt8(0), C.false, (*C.UInt8)(&buf[0]), maxBufLen, &usedBufLen)
	return string(buf[:usedBufLen])
}

// CFArrayToArray converts a CFArrayRef to an array of CFTypes
func CFArrayToArray(ref C.CFArrayRef) (a []C.CFTypeRef) {
	count := C.CFArrayGetCount(ref)
	if count > 0 {
		a = make([]C.CFTypeRef, count)
		C.CFArrayGetValues(ref, C.CFRange{0, count}, (*unsafe.Pointer)(unsafe.Pointer(&a[0])))
	}
	return
}

// CFTypeDescription returns type string for CFTypeRef
func CFTypeDescription(ref C.CFTypeRef) string {
	typeID := C.CFGetTypeID(ref)
	typeDesc := C.CFCopyTypeIDDescription(typeID)
	defer Release(C.CFTypeRef(typeDesc))
	return CFStringToString(typeDesc)
}

// Convert converts a CFTypeRef to a go value
func Convert(ref C.CFTypeRef) (interface{}, error) {
	typeID := C.CFGetTypeID(ref)
	if typeID == C.CFStringGetTypeID() {
		return CFStringToString(C.CFStringRef(ref)), nil
	} else if typeID == C.CFDictionaryGetTypeID() {
		return CFDictionaryToMap(C.CFDictionaryRef(ref))
	} else if typeID == C.CFArrayGetTypeID() {
		arr := CFArrayToArray(C.CFArrayRef(ref))
		results := make([]interface{}, 0, len(arr))
		for _, ref := range arr {
			v, err := Convert(ref)
			if err != nil {
				return nil, err
			}
			results = append(results, v)
			return results, nil
		}
	}
	return nil, fmt.Errorf("invalid type: %s", CFTypeDescription(ref))
}

// CFDictionaryToMap returns a regular go map
func CFDictionaryToMap(ref C.CFDictionaryRef) (map[interface{}]interface{}, error) {
	result := make(map[interface{}]interface{})
	for k, v := range CFDictionaryToPointerMap(ref) {
		gk, err := Convert(k)
		if err != nil {
			return nil, err
		}
		gv, err := Convert(v)
		if err != nil {
			return nil, err
		}
		result[gk] = gv
	}
	return result, nil
}

// ParseDNSResponse attempts to parse DNS response from dynamic store
func ParseDNSResponse(m map[interface{}]interface{}) ([]net.IP, error) {
	if m["ServerAddresses"] == nil {
		return nil, fmt.Errorf("empty server list")
	}
	var addrs []net.IP
	if slice, ok := m["ServerAddresses"].([]interface{}); ok {
		for _, addr := range slice {
			if str, ok := addr.(string); ok {
				ip := net.ParseIP(str)
				if ip == nil {
					continue
				}
				addrs = append(addrs, ip)
			}
		}
	}
	return addrs, nil
}

// ServerAddrs returns local DNS resolver IP addresses
func ServerAddrs() ([]net.IP, error) {
	// caller name for dynamic store
	caller, err := StringToCFString("com.romantomjak.resolver")
	if err != nil {
		panic(err)
	}
	defer Release(C.CFTypeRef(caller))

	// key to query system configuration
	key, err := StringToCFString("State:/Network/Global/DNS")
	if err != nil {
		panic(err)
	}
	defer Release(C.CFTypeRef(key))

	// create a new session used to interact with the dynamic store maintained
	// by the System Configuration server. the dynamic store contains, among
	// other items, information about the current network state
	store := C.SCDynamicStoreCreate(C.kCFAllocatorSystemDefault, caller, nil, nil)
	defer Release(C.CFTypeRef(store))

	val := C.SCDynamicStoreCopyValue(store, key)
	defer Release(C.CFTypeRef(val))

	config, err := CFDictionaryToMap(C.CFDictionaryRef(val))
	if err != nil {
		panic(err)
	}

	addrs, err := ParseDNSResponse(config)
	if err != nil {
		panic(err)
	}

	return addrs, nil
}
