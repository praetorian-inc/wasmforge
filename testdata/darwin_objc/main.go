// Test program for the purego/objc sysshim on macOS via WasmForge.
// Verifies ObjC message sending, NSString creation, and NSData handling.
//
// Build: GOOS=darwin GOARCH=amd64 wasmforge build -v -o /tmp/test-objc ./testdata/darwin_objc
// Run:   /tmp/test-objc

package main

import (
	"fmt"
	"os"

	"github.com/ebitengine/purego"
	"github.com/ebitengine/purego/objc"
)

func main() {
	passed := 0
	failed := 0

	// Test 1: Load Foundation framework
	foundation, err := purego.Dlopen("/System/Library/Frameworks/Foundation.framework/Foundation", purego.RTLD_LAZY)
	if err != nil {
		fmt.Fprintf(os.Stderr, "FAIL: Dlopen Foundation: %v\n", err)
		os.Exit(1)
	}
	_ = foundation
	fmt.Println("PASS: Dlopen Foundation")
	passed++

	// Test 2: Get NSString class
	nsStringClass := objc.GetClass("NSString")
	if nsStringClass == 0 {
		fmt.Fprintf(os.Stderr, "FAIL: GetClass NSString = 0\n")
		failed++
	} else {
		fmt.Printf("PASS: GetClass NSString = %#x\n", nsStringClass)
		passed++
	}

	// Test 3: Create NSString via stringWithUTF8String:
	selStringWithUTF8 := objc.RegisterName("stringWithUTF8String:")
	nsStr := objc.ID(nsStringClass).Send(selStringWithUTF8, "Hello, WasmForge!")
	if nsStr == 0 {
		fmt.Fprintf(os.Stderr, "FAIL: NSString stringWithUTF8String: returned nil\n")
		failed++
	} else {
		fmt.Printf("PASS: NSString created = %#x\n", nsStr)
		passed++
	}

	// Test 4: Get NSString length
	if nsStr != 0 {
		selLength := objc.RegisterName("length")
		length := objc.Send[uintptr](nsStr, selLength)
		if length == 17 { // "Hello, WasmForge!" = 17 chars
			fmt.Printf("PASS: NSString length = %d\n", length)
			passed++
		} else {
			fmt.Fprintf(os.Stderr, "FAIL: NSString length = %d, expected 17\n", length)
			failed++
		}
	}

	// Test 5: Get NSData class
	nsDataClass := objc.GetClass("NSData")
	if nsDataClass == 0 {
		fmt.Fprintf(os.Stderr, "FAIL: GetClass NSData = 0\n")
		failed++
	} else {
		fmt.Printf("PASS: GetClass NSData = %#x\n", nsDataClass)
		passed++
	}

	// Test 6: Get NSObject class
	nsObjectClass := objc.GetClass("NSObject")
	if nsObjectClass == 0 {
		fmt.Fprintf(os.Stderr, "FAIL: GetClass NSObject = 0\n")
		failed++
	} else {
		fmt.Printf("PASS: GetClass NSObject = %#x\n", nsObjectClass)
		passed++
	}

	// Test 7: Get NSURLSession class (typical transport bootstrapping)
	nsURLSessionClass := objc.GetClass("NSURLSession")
	if nsURLSessionClass == 0 {
		fmt.Fprintf(os.Stderr, "FAIL: GetClass NSURLSession = 0\n")
		failed++
	} else {
		fmt.Printf("PASS: GetClass NSURLSession = %#x\n", nsURLSessionClass)
		passed++
	}

	// Test 8: GetProtocol
	proto := objc.GetProtocol("NSURLSessionDelegate")
	if proto == nil {
		fmt.Fprintf(os.Stderr, "FAIL: GetProtocol NSURLSessionDelegate = nil\n")
		failed++
	} else {
		fmt.Printf("PASS: GetProtocol NSURLSessionDelegate = %p\n", proto)
		passed++
	}

	fmt.Printf("\n%d/%d tests passed\n", passed, passed+failed)
	if failed > 0 {
		os.Exit(1)
	}
}
