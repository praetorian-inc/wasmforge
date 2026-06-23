//go:build windows

package hostmod

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"sync"
	"unsafe"

	"github.com/tetratelabs/wazero/api"
	"golang.org/x/sys/windows"
)

// Extension callback IDs used by the guest to request native function addresses.
const (
	extFuncOutput      = 0
	extFuncPrintf      = 1
	extFuncDataParse   = 2
	extFuncDataInt     = 3
	extFuncDataShort   = 4
	extFuncDataLength  = 5
	extFuncDataExtract = 6
	extFuncAddValue    = 7
	extFuncGetValue    = 8
	extFuncRemoveValue = 9
	extFuncExtension   = 10
	extFuncMax         = 11
)

// extCallbackState holds the global state for extension API callbacks.
// All callbacks write output to the shared buffer, and the data parser family
// operates on native pointers in host memory (since object files run as native x64 code).
type extCallbackState struct {
	mu        sync.Mutex
	output    bytes.Buffer
	callbacks [extFuncMax]uintptr // native function pointers
	keyStore  map[string]uintptr
	inited    bool
}

var globalExtState extCallbackState

// initExtCallbacks creates native function pointers for all extension API
// functions using windows.NewCallback. These pointers can be written into
// an object file's GOT so it can call them at native speed.
func initExtCallbacks() {
	globalExtState.mu.Lock()
	defer globalExtState.mu.Unlock()

	if globalExtState.inited {
		return
	}
	globalExtState.keyStore = make(map[string]uintptr)

	// Output(int type, char* data, int len) → uintptr
	globalExtState.callbacks[extFuncOutput] = windows.NewCallback(
		func(outputType uintptr, data uintptr, length uintptr) uintptr {
			if length <= 0 {
				return 0
			}
			buf := make([]byte, length)
			copy(buf, (*[1 << 30]byte)(unsafe.Pointer(data))[:length])
			globalExtState.mu.Lock()
			globalExtState.output.Write(buf)
			globalExtState.mu.Unlock()
			return 1
		},
	)

	// Printf(int type, char* fmt, ...) → uintptr
	// Interpolates format string arguments. Supports %s (C string pointer),
	// %S/%ls (wide string pointer), %p (hex pointer), and standard integer
	// specifiers (%d, %u, %x, %X, %i, %c, %o, %ld, %lu, %lx, %lld, etc.).
	globalExtState.callbacks[extFuncPrintf] = windows.NewCallback(
		func(outputType uintptr, fmtStr uintptr, a0, a1, a2, a3, a4, a5, a6, a7, a8, a9 uintptr) uintptr {
			fmtS := readNativeString(fmtStr)
			args := [10]uintptr{a0, a1, a2, a3, a4, a5, a6, a7, a8, a9}
			result := nativeSprintf(fmtS, args[:])
			globalExtState.mu.Lock()
			globalExtState.output.WriteString(result)
			globalExtState.output.WriteByte('\n')
			globalExtState.mu.Unlock()
			return 0
		},
	)

	// datap struct layout (x64):
	//   offset 0: original uintptr (8 bytes)
	//   offset 8: buffer   uintptr (8 bytes)
	//   offset 16: length  uint32  (4 bytes)
	//   offset 20: size    uint32  (4 bytes)

	// DataParse(datap* parser, char* buffer, int size) → uintptr
	globalExtState.callbacks[extFuncDataParse] = windows.NewCallback(
		func(datap uintptr, buff uintptr, size uintptr) uintptr {
			if size <= 0 {
				return 0
			}
			// datap.original = buff
			*(*uintptr)(unsafe.Pointer(datap)) = buff
			// datap.buffer = buff + 4 (skip length prefix)
			*(*uintptr)(unsafe.Pointer(datap + 8)) = buff + 4
			// datap.length = size - 4
			*(*uint32)(unsafe.Pointer(datap + 16)) = uint32(size) - 4
			// datap.size = size - 4
			*(*uint32)(unsafe.Pointer(datap + 20)) = uint32(size) - 4
			return 1
		},
	)

	// DataInt(datap* parser) → uintptr
	globalExtState.callbacks[extFuncDataInt] = windows.NewCallback(
		func(datap uintptr) uintptr {
			bufPtr := *(*uintptr)(unsafe.Pointer(datap + 8))
			length := *(*uint32)(unsafe.Pointer(datap + 16))
			if length < 4 {
				return 0
			}
			value := *(*uint32)(unsafe.Pointer(bufPtr))
			*(*uintptr)(unsafe.Pointer(datap + 8)) = bufPtr + 4
			*(*uint32)(unsafe.Pointer(datap + 16)) = length - 4
			return uintptr(value)
		},
	)

	// DataShort(datap* parser) → uintptr
	globalExtState.callbacks[extFuncDataShort] = windows.NewCallback(
		func(datap uintptr) uintptr {
			bufPtr := *(*uintptr)(unsafe.Pointer(datap + 8))
			length := *(*uint32)(unsafe.Pointer(datap + 16))
			if length < 2 {
				return 0
			}
			value := *(*uint16)(unsafe.Pointer(bufPtr))
			*(*uintptr)(unsafe.Pointer(datap + 8)) = bufPtr + 2
			*(*uint32)(unsafe.Pointer(datap + 16)) = length - 2
			return uintptr(value)
		},
	)

	// DataLength(datap* parser) → uintptr
	globalExtState.callbacks[extFuncDataLength] = windows.NewCallback(
		func(datap uintptr) uintptr {
			length := *(*uint32)(unsafe.Pointer(datap + 16))
			return uintptr(length)
		},
	)

	// DataExtract(datap* parser, int* outSize) → uintptr
	globalExtState.callbacks[extFuncDataExtract] = windows.NewCallback(
		func(datap uintptr, outSize uintptr) uintptr {
			bufPtr := *(*uintptr)(unsafe.Pointer(datap + 8))
			length := *(*uint32)(unsafe.Pointer(datap + 16))
			if length < 4 {
				return 0
			}
			blobLen := *(*uint32)(unsafe.Pointer(bufPtr))
			bufPtr += 4
			length -= 4
			if length < blobLen {
				return 0
			}
			if outSize != 0 && blobLen != 0 {
				*(*uint32)(unsafe.Pointer(outSize)) = blobLen
			}
			result := bufPtr
			*(*uintptr)(unsafe.Pointer(datap + 8)) = bufPtr + uintptr(blobLen)
			*(*uint32)(unsafe.Pointer(datap + 16)) = length - blobLen
			return result
		},
	)

	// AddValue(char* key, uintptr ptr) → uintptr
	globalExtState.callbacks[extFuncAddValue] = windows.NewCallback(
		func(key uintptr, ptr uintptr) uintptr {
			sKey := readNativeString(key)
			globalExtState.mu.Lock()
			globalExtState.keyStore[sKey] = ptr
			globalExtState.mu.Unlock()
			return 1
		},
	)

	// GetValue(char* key) → uintptr
	globalExtState.callbacks[extFuncGetValue] = windows.NewCallback(
		func(key uintptr) uintptr {
			sKey := readNativeString(key)
			globalExtState.mu.Lock()
			v := globalExtState.keyStore[sKey]
			globalExtState.mu.Unlock()
			return v
		},
	)

	// RemoveValue(char* key) → uintptr
	globalExtState.callbacks[extFuncRemoveValue] = windows.NewCallback(
		func(key uintptr) uintptr {
			sKey := readNativeString(key)
			globalExtState.mu.Lock()
			_, exists := globalExtState.keyStore[sKey]
			if exists {
				delete(globalExtState.keyStore, sKey)
			}
			globalExtState.mu.Unlock()
			if exists {
				return 1
			}
			return 0
		},
	)

	// Extension callback: func(data uintptr, dataLen uintptr) uintptr
	// Sliver's extension API uses this 2-arg signature (not the 3-arg
	// BeaconOutput). The coff-loader calls callback(dataPtr, dataLen).
	globalExtState.callbacks[extFuncExtension] = windows.NewCallback(
		func(data uintptr, length uintptr) uintptr {
			if length <= 0 {
				return 0
			}
			buf := make([]byte, length)
			copy(buf, (*[1 << 30]byte)(unsafe.Pointer(data))[:length])
			globalExtState.mu.Lock()
			globalExtState.output.Write(buf)
			globalExtState.mu.Unlock()
			return 1
		},
	)

	globalExtState.inited = true
}

// nativeSprintf interpolates a C-style format string with native pointer/integer arguments.
// Handles %s (ANSI string), %S/%ls (wide string), %p (pointer), and integer specifiers
// (%d, %u, %x, %X, %i, %c, %o, and their l/ll variants).
func nativeSprintf(format string, args []uintptr) string {
	var out bytes.Buffer
	argIdx := 0
	i := 0
	for i < len(format) {
		if format[i] != '%' {
			out.WriteByte(format[i])
			i++
			continue
		}
		// Found '%' — parse the format specifier.
		if i+1 >= len(format) {
			out.WriteByte('%')
			i++
			continue
		}
		i++ // skip '%'

		// Handle '%%' escape.
		if format[i] == '%' {
			out.WriteByte('%')
			i++
			continue
		}

		// Skip flags: '-', '+', ' ', '#', '0'
		for i < len(format) && (format[i] == '-' || format[i] == '+' || format[i] == ' ' || format[i] == '#' || format[i] == '0') {
			i++
		}
		// Skip width digits.
		for i < len(format) && format[i] >= '0' && format[i] <= '9' {
			i++
		}
		// Skip precision (.digits).
		if i < len(format) && format[i] == '.' {
			i++
			for i < len(format) && format[i] >= '0' && format[i] <= '9' {
				i++
			}
		}
		// Track length modifiers (needed to distinguish %s vs %ls).
		hasLongMod := false
		for i < len(format) && (format[i] == 'l' || format[i] == 'h' || format[i] == 'z' || format[i] == 'I') {
			if format[i] == 'l' {
				hasLongMod = true
			}
			i++
			// Handle I64
			if i < len(format) && format[i] >= '0' && format[i] <= '9' {
				for i < len(format) && format[i] >= '0' && format[i] <= '9' {
					i++
				}
			}
		}

		if i >= len(format) {
			break
		}

		spec := format[i]
		i++

		// Unknown specifiers do not consume arguments — emit literally.
		consumesArg := spec == 's' || spec == 'S' || spec == 'p' ||
			spec == 'd' || spec == 'i' || spec == 'u' ||
			spec == 'x' || spec == 'X' || spec == 'o' || spec == 'c'
		if !consumesArg {
			out.WriteByte('%')
			out.WriteByte(spec)
			continue
		}

		if argIdx >= len(args) {
			out.WriteString("<missing arg>")
			continue
		}
		arg := args[argIdx]
		argIdx++

		switch spec {
		case 's':
			if hasLongMod {
				// %ls — wchar_t* (wide string), same as %S.
				if arg == 0 {
					out.WriteString("(null)")
				} else {
					s := readNativeWideString(arg)
					out.WriteString(s)
				}
			} else {
				// %s — char* (ANSI C string).
				if arg == 0 {
					out.WriteString("(null)")
				} else {
					s := readNativeString(arg)
					out.WriteString(s)
				}
			}
		case 'S':
			// %S — wchar_t* (wide string).
			if arg == 0 {
				out.WriteString("(null)")
			} else {
				s := readNativeWideString(arg)
				out.WriteString(s)
			}
		case 'p':
			out.WriteString(fmt.Sprintf("0x%x", arg))
		case 'd', 'i':
			out.WriteString(fmt.Sprintf("%d", int64(arg)))
		case 'u':
			out.WriteString(fmt.Sprintf("%d", uint64(arg)))
		case 'x':
			out.WriteString(fmt.Sprintf("%x", uint64(arg)))
		case 'X':
			out.WriteString(fmt.Sprintf("%X", uint64(arg)))
		case 'o':
			out.WriteString(fmt.Sprintf("%o", uint64(arg)))
		case 'c':
			out.WriteByte(byte(arg))
		default:
			out.WriteString(fmt.Sprintf("%%%c", spec))
		}
	}
	return out.String()
}

// readNativeWideString reads a null-terminated UTF-16LE string from a native pointer.
func readNativeWideString(ptr uintptr) string {
	if ptr == 0 {
		return ""
	}
	var runes []rune
	for i := uintptr(0); ; i += 2 {
		lo := *(*byte)(unsafe.Pointer(ptr + i))
		hi := *(*byte)(unsafe.Pointer(ptr + i + 1))
		ch := uint16(lo) | uint16(hi)<<8
		if ch == 0 {
			break
		}
		runes = append(runes, rune(ch))
	}
	return string(runes)
}

// readNativeString reads a null-terminated C string from a native pointer.
func readNativeString(ptr uintptr) string {
	if ptr == 0 {
		return ""
	}
	var buf []byte
	for i := uintptr(0); ; i++ {
		c := *(*byte)(unsafe.Pointer(ptr + i))
		if c == 0 {
			break
		}
		buf = append(buf, c)
	}
	return string(buf)
}

// win32ExtGetFunc returns the native address of an extension API callback function.
// The guest uses this to populate the GOT entries when loading an object file.
// funcId identifies which function, addrPtr receives the uint64 address.
func win32ExtGetFunc(ctx context.Context, mod api.Module, funcId uint32, addrPtr uint32) uint32 {
	cfg := getConfig(ctx)
	if cfg == nil || !cfg.Win32APIs {
		return errnoENOSYS
	}

	if funcId >= extFuncMax {
		return errnoEINVAL
	}

	initExtCallbacks()

	globalExtState.mu.Lock()
	addr := globalExtState.callbacks[funcId]
	globalExtState.mu.Unlock()
	if addr == 0 {
		return errnoEINVAL
	}

	var buf [8]byte
	binary.LittleEndian.PutUint64(buf[:], uint64(addr))
	if !writeBytes(mod, addrPtr, buf[:]) {
		return errnoEFAULT
	}
	return errnoSuccess
}

// win32ExtReadOutput reads accumulated extension output into WASM memory.
// bufPtr/bufLen is the destination buffer, actualLenPtr receives the bytes written.
// If the buffer is too small, the output is truncated but the full length is reported.
func win32ExtReadOutput(ctx context.Context, mod api.Module, bufPtr, bufLen, actualLenPtr uint32) uint32 {
	cfg := getConfig(ctx)
	if cfg == nil || !cfg.Win32APIs {
		return errnoENOSYS
	}

	globalExtState.mu.Lock()
	snapshot := make([]byte, globalExtState.output.Len())
	copy(snapshot, globalExtState.output.Bytes())
	actualLen := uint32(len(snapshot))
	globalExtState.mu.Unlock()

	if !writeUint32(mod, actualLenPtr, actualLen) {
		return errnoEFAULT
	}

	copyLen := actualLen
	if copyLen > bufLen {
		copyLen = bufLen
	}
	if copyLen > 0 {
		if !writeBytes(mod, bufPtr, snapshot[:copyLen]) {
			return errnoEFAULT
		}
	}
	return errnoSuccess
}

// win32ExtResetOutput clears the accumulated extension output buffer.
func win32ExtResetOutput(ctx context.Context, mod api.Module) uint32 {
	cfg := getConfig(ctx)
	if cfg == nil || !cfg.Win32APIs {
		return errnoENOSYS
	}

	globalExtState.mu.Lock()
	globalExtState.output.Reset()
	globalExtState.mu.Unlock()
	return errnoSuccess
}

// callbackNameMap maps keyword suffixes found in Go function names to
// Extension API callback IDs. NewCallback on wasip1 uses runtime.FuncForPC
// to get the function name and sends it as a hint to this host function.
var callbackNameMap = map[string]uint32{
	"Output":            extFuncOutput,
	"Printf":            extFuncPrintf,
	"DataParse":         extFuncDataParse,
	"DataInt":           extFuncDataInt,
	"DataShort":         extFuncDataShort,
	"DataLength":        extFuncDataLength,
	"DataExtract":       extFuncDataExtract,
	"AddValue":          extFuncAddValue,
	"GetValue":          extFuncGetValue,
	"RemoveValue":       extFuncRemoveValue,
	"ExtensionCallback": extFuncExtension,
	"extensionCallback": extFuncExtension,
}

// win32NewCallback maps a Go function name hint to an Extension API native
// callback address. The WASM-side NewCallback uses runtime.FuncForPC to extract
// the function name and sends it as a hint. The host matches keywords in the
// name against known Beacon API callback patterns and returns the corresponding
// native function pointer.
//
// Parameters: namePtr, nameLen = hint string; addrPtr = output uint64 address.
// Returns 0 on success, errnoENOSYS if Win32 APIs disabled, errnoEINVAL if
// no matching callback found.
func win32NewCallback(ctx context.Context, mod api.Module, namePtr, nameLen, addrPtr uint32) uint32 {
	cfg := getConfig(ctx)
	if cfg == nil || !cfg.Win32APIs {
		return errnoENOSYS
	}

	// Read the hint name from WASM memory.
	var hint string
	if nameLen > 0 {
		data, ok := readBytes(mod, namePtr, nameLen)
		if !ok {
			return errnoEFAULT
		}
		hint = string(data)
	}

	initExtCallbacks()

	// Match hint against known callback names by checking for keyword suffixes.
	var matchedID uint32 = extFuncMax // sentinel: no match
	for keyword, id := range callbackNameMap {
		if containsKeyword(hint, keyword) {
			matchedID = id
			break
		}
	}

	if matchedID >= extFuncMax {
		// No matching callback found. Return 0 address (caller handles it).
		var buf [8]byte
		if !writeBytes(mod, addrPtr, buf[:]) {
			return errnoEFAULT
		}
		return errnoSuccess
	}

	globalExtState.mu.Lock()
	addr := globalExtState.callbacks[matchedID]
	globalExtState.mu.Unlock()

	var buf [8]byte
	binary.LittleEndian.PutUint64(buf[:], uint64(addr))
	if !writeBytes(mod, addrPtr, buf[:]) {
		return errnoEFAULT
	}
	return errnoSuccess
}

// containsKeyword checks if the hint string contains the keyword as a
// standalone component (preceded by a dot, underscore, uppercase letter
// boundary, or start of string). CamelCase boundaries are recognized so
// that "GetCoffPrintfForChannel" matches the keyword "Printf".
func containsKeyword(hint, keyword string) bool {
	idx := 0
	for {
		pos := indexFrom(hint, keyword, idx)
		if pos < 0 {
			return false
		}
		// Check that keyword appears at a word boundary.
		if pos == 0 || hint[pos-1] == '.' || hint[pos-1] == '_' {
			return true
		}
		// CamelCase boundary: keyword starts with uppercase and previous char is lowercase.
		if len(keyword) > 0 && keyword[0] >= 'A' && keyword[0] <= 'Z' &&
			hint[pos-1] >= 'a' && hint[pos-1] <= 'z' {
			return true
		}
		idx = pos + 1
	}
}

func indexFrom(s, substr string, start int) int {
	if start >= len(s) {
		return -1
	}
	for i := start; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}
