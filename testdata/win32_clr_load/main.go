// win32_clr_load tests _AppDomain::Load_3 with a real .NET assembly.
// Uses ICorRuntimeHost + SyscallN (the standard go-clr pattern).
//
// Build: GOOS=windows GOARCH=amd64 wasmforge build --win32-apis -v -o clr_load.exe ./testdata/win32_clr_load
// Run: Copy Seatbelt.exe to C:\Temp\ on Win11, then run clr_load.exe
package main

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"os"
	"syscall"
	"unsafe"
)

type GUID struct {
	Data1 uint32
	Data2 uint16
	Data3 uint16
	Data4 [8]byte
}

var (
	ole32   = syscall.NewLazyDLL("ole32.dll")
	mscoree = syscall.NewLazyDLL("mscoree.dll")
	oleaut  = syscall.NewLazyDLL("oleaut32.dll")
	ntdll   = syscall.NewLazyDLL("ntdll.dll")

	procCoInitializeEx    = ole32.NewProc("CoInitializeEx")
	procCLRCreateInstance = mscoree.NewProc("CLRCreateInstance")
	procSafeArrayCreate   = oleaut.NewProc("SafeArrayCreateVector")
	procSafeArrayAccess   = oleaut.NewProc("SafeArrayAccessData")
	procSafeArrayUnaccess = oleaut.NewProc("SafeArrayUnaccessData")
	procSafeArrayDestroy  = oleaut.NewProc("SafeArrayDestroy")
	procRtlMoveMemory     = ntdll.NewProc("RtlMoveMemory")
)

const VT_UI1 = 17

var (
	CLSID_CLRMetaHost = GUID{0x9280188d, 0xe8e, 0x4867, [8]byte{0xb3, 0x0c, 0x7f, 0xa8, 0x38, 0x84, 0xe8, 0xde}}
	IID_ICLRMetaHost  = GUID{0xD332DB9E, 0xB9B3, 0x4125, [8]byte{0x82, 0x07, 0xA1, 0x48, 0x84, 0xF5, 0x32, 0x16}}

	CLSID_CorRuntimeHost = GUID{0xCB2F6723, 0xAB3A, 0x11D2, [8]byte{0x9C, 0x40, 0x00, 0xC0, 0x4F, 0xA3, 0x0A, 0x3E}}
	IID_ICorRuntimeHost  = GUID{0xCB2F6722, 0xAB3A, 0x11D2, [8]byte{0x9C, 0x40, 0x00, 0xC0, 0x4F, 0xA3, 0x0A, 0x3E}}

	IID_AppDomain = GUID{0x05F696DC, 0x2B29, 0x3663, [8]byte{0xAD, 0x8B, 0xC4, 0x38, 0x9C, 0xF2, 0xA7, 0x13}}
)

func comCall(iface uintptr, vtableIdx int, args ...uintptr) (uintptr, uintptr, syscall.Errno) {
	vtable := *(*uintptr)(unsafe.Pointer(iface))
	method := *(*uintptr)(unsafe.Pointer(vtable + uintptr(vtableIdx)*unsafe.Sizeof(uintptr(0))))
	allArgs := make([]uintptr, 0, 1+len(args))
	allArgs = append(allArgs, iface)
	allArgs = append(allArgs, args...)
	return syscall.SyscallN(method, allArgs...)
}

func utf16Ptr(s string) *uint16 {
	p, _ := syscall.UTF16PtrFromString(s)
	return p
}

// dumpSAStruct reads and dumps a SAFEARRAY struct from WASM memory.
func dumpSAStruct(sa uintptr) {
	raw := unsafe.Slice((*byte)(unsafe.Pointer(sa)), 32)
	fmt.Printf("  SAFEARRAY raw: %x\n", raw)
	cDims := binary.LittleEndian.Uint16(raw[0:2])
	fFeatures := binary.LittleEndian.Uint16(raw[2:4])
	cbElements := binary.LittleEndian.Uint32(raw[4:8])
	cLocks := binary.LittleEndian.Uint32(raw[8:12])
	pvData := binary.LittleEndian.Uint64(raw[16:24])
	cElements := binary.LittleEndian.Uint32(raw[24:28])
	lLbound := binary.LittleEndian.Uint32(raw[28:32])
	fmt.Printf("  cDims=%d fFeatures=0x%x cbElements=%d cLocks=%d pvData=0x%x cElements=%d lLbound=%d\n",
		cDims, fFeatures, cbElements, cLocks, pvData, cElements, lLbound)
}

func main() {
	fmt.Println("=== CLR Load_3 Test ===")

	// Read assembly — try Seatbelt first (large assembly to test pointer mask fix).
	paths := []string{
		`C:\Temp\Seatbelt.exe`, "/c/Temp/Seatbelt.exe",
		`C:\Temp\Hello.exe`, "/c/Temp/Hello.exe",
	}
	var asmPath string
	var asmData []byte
	for _, p := range paths {
		data, err2 := os.ReadFile(p)
		if err2 == nil {
			asmPath = p
			asmData = data
			break
		}
	}
	if asmData == nil {
		fmt.Println("FAIL: cannot read any assembly")
		os.Exit(1)
	}
	_ = asmPath
	origHash := sha256.Sum256(asmData)
	fmt.Printf("Assembly: %d bytes, first4=%x sha256=%x\n", len(asmData), asmData[:4], origHash[:8])

	// CoInitializeEx
	procCoInitializeEx.Call(0, 0)

	// CLRCreateInstance → ICLRMetaHost
	var pMetaHost uintptr
	hr, _, _ := procCLRCreateInstance.Call(
		uintptr(unsafe.Pointer(&CLSID_CLRMetaHost)),
		uintptr(unsafe.Pointer(&IID_ICLRMetaHost)),
		uintptr(unsafe.Pointer(&pMetaHost)),
	)
	if hr != 0 {
		fmt.Printf("FAIL: CLRCreateInstance hr=0x%x\n", hr)
		os.Exit(1)
	}
	fmt.Printf("CLRCreateInstance: pMetaHost=0x%x\n", pMetaHost)

	// GetRuntime (slot 3)
	var pRuntimeInfo uintptr
	var IID_ICLRRuntimeInfo = GUID{0xBD39D1D2, 0xBA2F, 0x486a, [8]byte{0x89, 0xB0, 0xB4, 0xB0, 0xCB, 0x46, 0x68, 0x91}}
	hr, _, _ = comCall(pMetaHost, 3,
		uintptr(unsafe.Pointer(utf16Ptr("v4.0.30319"))),
		uintptr(unsafe.Pointer(&IID_ICLRRuntimeInfo)),
		uintptr(unsafe.Pointer(&pRuntimeInfo)),
	)
	if hr != 0 {
		fmt.Printf("FAIL: GetRuntime hr=0x%x\n", hr)
		os.Exit(1)
	}
	fmt.Printf("GetRuntime: pRuntimeInfo=0x%x\n", pRuntimeInfo)

	// GetInterface → ICorRuntimeHost (slot 9)
	var pCorHost uintptr
	hr, _, _ = comCall(pRuntimeInfo, 9,
		uintptr(unsafe.Pointer(&CLSID_CorRuntimeHost)),
		uintptr(unsafe.Pointer(&IID_ICorRuntimeHost)),
		uintptr(unsafe.Pointer(&pCorHost)),
	)
	if hr != 0 {
		fmt.Printf("FAIL: GetInterface hr=0x%x\n", hr)
		os.Exit(1)
	}
	fmt.Printf("GetInterface: pCorHost=0x%x\n", pCorHost)

	comCall(pMetaHost, 2)
	comCall(pRuntimeInfo, 2)

	// Start (slot 10)
	hr, _, _ = comCall(pCorHost, 10)
	fmt.Printf("Start: hr=0x%x\n", hr)

	// GetDefaultDomain (slot 13)
	var pDomainThunk uintptr
	hr, _, _ = comCall(pCorHost, 13, uintptr(unsafe.Pointer(&pDomainThunk)))
	if hr != 0 {
		fmt.Printf("FAIL: GetDefaultDomain hr=0x%x\n", hr)
		os.Exit(1)
	}
	fmt.Printf("GetDefaultDomain: pDomainThunk=0x%x\n", pDomainThunk)

	// QI _AppDomain (slot 0)
	var pAppDomain uintptr
	hr, _, _ = comCall(pDomainThunk, 0,
		uintptr(unsafe.Pointer(&IID_AppDomain)),
		uintptr(unsafe.Pointer(&pAppDomain)),
	)
	if hr != 0 {
		fmt.Printf("FAIL: QI _AppDomain hr=0x%x\n", hr)
		os.Exit(1)
	}
	fmt.Printf("QI _AppDomain: pAppDomain=0x%x\n", pAppDomain)

	// SafeArrayCreateVector (SyscallN for 64-bit return)
	sa, _, _ := syscall.SyscallN(procSafeArrayCreate.Addr(), VT_UI1, 0, uintptr(len(asmData)))
	if sa == 0 {
		fmt.Println("FAIL: SafeArrayCreateVector returned NULL")
		os.Exit(1)
	}
	fmt.Printf("SafeArrayCreate: sa=0x%x\n", sa)
	dumpSAStruct(sa)

	// SafeArrayAccessData
	var ppData uintptr
	hr, _, _ = syscall.SyscallN(procSafeArrayAccess.Addr(), sa, uintptr(unsafe.Pointer(&ppData)))
	if hr != 0 {
		fmt.Printf("FAIL: SafeArrayAccessData hr=0x%x\n", hr)
		os.Exit(1)
	}
	fmt.Printf("SafeArrayAccessData: ppData=0x%x\n", ppData)

	// Copy data
	syscall.SyscallN(procRtlMoveMemory.Addr(), ppData, uintptr(unsafe.Pointer(&asmData[0])), uintptr(len(asmData)))

	// Verify in WASM
	pvSlice := unsafe.Slice((*byte)(unsafe.Pointer(ppData)), len(asmData))
	vHash := sha256.Sum256(pvSlice)
	fmt.Printf("pvData verify: first4=%x sha256=%x match=%v\n", pvSlice[:4], vHash[:8], vHash == origHash)

	// Unaccess
	syscall.SyscallN(procSafeArrayUnaccess.Addr(), sa)

	// Dump SAFEARRAY struct right before Load_3
	fmt.Println("=== Pre-Load_3 SAFEARRAY dump ===")
	dumpSAStruct(sa)

	// Also read pvData again after unaccess to verify it's still there
	// Read pvData pointer from SAFEARRAY struct
	saBytes := unsafe.Slice((*byte)(unsafe.Pointer(sa)), 32)
	pvDataPtr := binary.LittleEndian.Uint64(saBytes[16:24])
	fmt.Printf("pvData ptr from struct: 0x%x\n", pvDataPtr)
	if pvDataPtr > 0 && pvDataPtr < 0x7FFFFFFFFFFF {
		pvSlice2 := unsafe.Slice((*byte)(unsafe.Pointer(uintptr(pvDataPtr))), 16)
		fmt.Printf("pvData first16 (post-unaccess): %x\n", pvSlice2)
	}

	// Load_3 (slot 45)
	var pAssembly uintptr
	fmt.Printf("\nCalling Load_3: pAppDomain=0x%x sa=0x%x\n", pAppDomain, sa)
	hr, _, _ = comCall(pAppDomain, 45,
		sa,
		uintptr(unsafe.Pointer(&pAssembly)),
	)
	fmt.Printf("Load_3: hr=0x%x pAssembly=0x%x\n", hr, pAssembly)

	if hr != 0 {
		fmt.Printf("FAIL: Load_3 hr=0x%x (E_BAD_IMGFMT=0x8007000B)\n", hr)
		os.Exit(1)
	}

	fmt.Printf("PASS: Load_3 succeeded! pAssembly=0x%x\n", pAssembly)
	fmt.Println("\nPASS: CLR Load_3 test complete")
}
