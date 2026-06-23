package hostmod

import (
	"context"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
)

// registerWin32Functions adds all Win32 API bridge host functions to the
// provided builder and returns the extended builder.
//
// The following functions are registered (with WASM export names):
//
//	win32_available        ()            → i32
//	win32_load_library     (i32,i32,i32) → i32
//	win32_get_proc_address (i32,i32,i32,i32) → i32
//	win32_call             (i32,i32,i32,i32) → i32
//	win32_free_library     (i32)         → i32
//	win32_reg_open_key     (i32,i32,i32,i32,i32) → i32
//	win32_reg_close_key    (i32)         → i32
//	win32_reg_query_value  (i32,i32,i32,i32,i32,i32) → i32
//	win32_reg_set_value    (i32,i32,i32,i32,i32,i32) → i32
//	win32_reg_delete_value (i32,i32,i32) → i32
//	win32_reg_enum_key     (i32,i32,i32,i32) → i32
//	win32_get_computer_name (i32,i32)    → i32
//	win32_create_process   (i32,i32,i32,i32,i32) → i32
//	win32_open_process     (i32,i32,i32) → i32
//	win32_terminate_process (i32,i32)   → i32
//	win32_close_handle     (i32)        → i32
//	win32_create_file      (i32,i32,i32,i32,i32,i32,i32) → i32
//	win32_read_file        (i32,i32,i32,i32) → i32
//	win32_write_file       (i32,i32,i32,i32) → i32
//	win32_get_file_attrs   (i32,i32,i32) → i32
//	win32_set_file_attrs   (i32,i32,i32) → i32
//	win32_find_files       (i32,i32,i32,i32,i32,i32,i32,i32,i32) → i32
//	win32_open_process_token (i32,i32,i32) → i32
//	win32_get_token_info   (i32,i32,i32,i32,i32) → i32
//	win32_open_sc_manager  (i32,i32,i32,i32) → i32
//	win32_query_service_status (i32,i32) → i32
//	win32_syscalln             (i32,i32,i32,i32,i32,i32) → i32
//	win32_virtual_alloc        (i32,i32,i32,i32) → i32
//	win32_virtual_protect      (i32,i32,i32) → i32
//	win32_virtual_free         (i32) → i32
//	win32_hmem_write           (i32,i32,i32,i32) → i32
//	win32_hmem_read            (i32,i32,i32,i32) → i32
//	win32_hmem_write32         (i32,i32,i32) → i32
//	win32_hmem_write64         (i32,i32,i32) → i32
//	win32_hmem_read32          (i32,i32,i32) → i32
//	win32_hmem_read64          (i32,i32,i32) → i32
//	win32_hmem_addr            (i32,i32) → i32
func registerWin32Functions(b wazero.HostModuleBuilder) wazero.HostModuleBuilder {
	return b.
		// win32_available: () → i32
		NewFunctionBuilder().
		WithGoModuleFunction(api.GoModuleFunc(func(ctx context.Context, mod api.Module, stack []uint64) {
			stack[0] = uint64(win32Available(ctx, mod))
		}), []api.ValueType{}, []api.ValueType{api.ValueTypeI32}).
		Export(export("win32_available")).

		// win32_load_library: name_ptr, name_len, handle_ptr → errno
		NewFunctionBuilder().
		WithGoModuleFunction(api.GoModuleFunc(func(ctx context.Context, mod api.Module, stack []uint64) {
			namePtr := uint32(stack[0])
			nameLen := uint32(stack[1])
			handlePtr := uint32(stack[2])
			stack[0] = uint64(win32LoadLibrary(ctx, mod, namePtr, nameLen, handlePtr))
		}), []api.ValueType{api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32}, []api.ValueType{api.ValueTypeI32}).
		WithParameterNames("name_ptr", "name_len", "handle_ptr").
		Export(export("win32_load_library")).

		// win32_get_proc_address: lib_handle, name_ptr, name_len, proc_ptr → errno
		NewFunctionBuilder().
		WithGoModuleFunction(api.GoModuleFunc(func(ctx context.Context, mod api.Module, stack []uint64) {
			libHandle := int32(stack[0])
			namePtr := uint32(stack[1])
			nameLen := uint32(stack[2])
			procPtr := uint32(stack[3])
			stack[0] = uint64(win32GetProcAddress(ctx, mod, libHandle, namePtr, nameLen, procPtr))
		}), []api.ValueType{api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32}, []api.ValueType{api.ValueTypeI32}).
		WithParameterNames("lib_handle", "name_ptr", "name_len", "proc_ptr").
		Export(export("win32_get_proc_address")).

		// win32_call: proc, nargs, args_ptr, ret_ptr → errno
		NewFunctionBuilder().
		WithGoModuleFunction(api.GoModuleFunc(func(ctx context.Context, mod api.Module, stack []uint64) {
			proc := int32(stack[0])
			nargs := uint32(stack[1])
			argsPtr := uint32(stack[2])
			retPtr := uint32(stack[3])
			stack[0] = uint64(win32Call(ctx, mod, proc, nargs, argsPtr, retPtr))
		}), []api.ValueType{api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32}, []api.ValueType{api.ValueTypeI32}).
		WithParameterNames("proc", "nargs", "args_ptr", "ret_ptr").
		Export(export("win32_call")).

		// win32_free_library: handle → errno
		NewFunctionBuilder().
		WithGoModuleFunction(api.GoModuleFunc(func(ctx context.Context, mod api.Module, stack []uint64) {
			handle := int32(stack[0])
			stack[0] = uint64(win32FreeLibrary(ctx, mod, handle))
		}), []api.ValueType{api.ValueTypeI32}, []api.ValueType{api.ValueTypeI32}).
		WithParameterNames("handle").
		Export(export("win32_free_library")).

		// win32_reg_open_key: hkey, subkey_ptr, subkey_len, access, handle_ptr → errno
		NewFunctionBuilder().
		WithGoModuleFunction(api.GoModuleFunc(func(ctx context.Context, mod api.Module, stack []uint64) {
			hkey := int32(stack[0])
			subkeyPtr := uint32(stack[1])
			subkeyLen := uint32(stack[2])
			access := uint32(stack[3])
			handlePtr := uint32(stack[4])
			stack[0] = uint64(win32RegOpenKey(ctx, mod, hkey, subkeyPtr, subkeyLen, access, handlePtr))
		}), []api.ValueType{api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32}, []api.ValueType{api.ValueTypeI32}).
		WithParameterNames("hkey", "subkey_ptr", "subkey_len", "access", "handle_ptr").
		Export(export("win32_reg_open_key")).

		// win32_reg_close_key: handle → errno
		NewFunctionBuilder().
		WithGoModuleFunction(api.GoModuleFunc(func(ctx context.Context, mod api.Module, stack []uint64) {
			handle := int32(stack[0])
			stack[0] = uint64(win32RegCloseKey(ctx, mod, handle))
		}), []api.ValueType{api.ValueTypeI32}, []api.ValueType{api.ValueTypeI32}).
		WithParameterNames("handle").
		Export(export("win32_reg_close_key")).

		// win32_reg_query_value: handle, name_ptr, name_len, type_ptr, data_ptr, data_len_ptr → errno
		NewFunctionBuilder().
		WithGoModuleFunction(api.GoModuleFunc(func(ctx context.Context, mod api.Module, stack []uint64) {
			handle := int32(stack[0])
			namePtr := uint32(stack[1])
			nameLen := uint32(stack[2])
			typePtr := uint32(stack[3])
			dataPtr := uint32(stack[4])
			dataLenPtr := uint32(stack[5])
			stack[0] = uint64(win32RegQueryValue(ctx, mod, handle, namePtr, nameLen, typePtr, dataPtr, dataLenPtr))
		}), []api.ValueType{api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32}, []api.ValueType{api.ValueTypeI32}).
		WithParameterNames("handle", "name_ptr", "name_len", "type_ptr", "data_ptr", "data_len_ptr").
		Export(export("win32_reg_query_value")).

		// win32_reg_set_value: handle, name_ptr, name_len, vtype, data_ptr, data_len → errno
		NewFunctionBuilder().
		WithGoModuleFunction(api.GoModuleFunc(func(ctx context.Context, mod api.Module, stack []uint64) {
			handle := int32(stack[0])
			namePtr := uint32(stack[1])
			nameLen := uint32(stack[2])
			vtype := uint32(stack[3])
			dataPtr := uint32(stack[4])
			dataLen := uint32(stack[5])
			stack[0] = uint64(win32RegSetValue(ctx, mod, handle, namePtr, nameLen, vtype, dataPtr, dataLen))
		}), []api.ValueType{api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32}, []api.ValueType{api.ValueTypeI32}).
		WithParameterNames("handle", "name_ptr", "name_len", "vtype", "data_ptr", "data_len").
		Export(export("win32_reg_set_value")).

		// win32_reg_delete_value: handle, name_ptr, name_len → errno
		NewFunctionBuilder().
		WithGoModuleFunction(api.GoModuleFunc(func(ctx context.Context, mod api.Module, stack []uint64) {
			handle := int32(stack[0])
			namePtr := uint32(stack[1])
			nameLen := uint32(stack[2])
			stack[0] = uint64(win32RegDeleteValue(ctx, mod, handle, namePtr, nameLen))
		}), []api.ValueType{api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32}, []api.ValueType{api.ValueTypeI32}).
		WithParameterNames("handle", "name_ptr", "name_len").
		Export(export("win32_reg_delete_value")).

		// win32_reg_enum_key: handle, index, name_ptr, name_len_ptr → errno
		NewFunctionBuilder().
		WithGoModuleFunction(api.GoModuleFunc(func(ctx context.Context, mod api.Module, stack []uint64) {
			handle := int32(stack[0])
			index := uint32(stack[1])
			namePtr := uint32(stack[2])
			nameLenPtr := uint32(stack[3])
			stack[0] = uint64(win32RegEnumKey(ctx, mod, handle, index, namePtr, nameLenPtr))
		}), []api.ValueType{api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32}, []api.ValueType{api.ValueTypeI32}).
		WithParameterNames("handle", "index", "name_ptr", "name_len_ptr").
		Export(export("win32_reg_enum_key")).

		// win32_get_computer_name: buf_ptr, buf_len_ptr → errno
		NewFunctionBuilder().
		WithGoModuleFunction(api.GoModuleFunc(func(ctx context.Context, mod api.Module, stack []uint64) {
			bufPtr := uint32(stack[0])
			bufLenPtr := uint32(stack[1])
			stack[0] = uint64(win32GetComputerName(ctx, mod, bufPtr, bufLenPtr))
		}), []api.ValueType{api.ValueTypeI32, api.ValueTypeI32}, []api.ValueType{api.ValueTypeI32}).
		WithParameterNames("buf_ptr", "buf_len_ptr").
		Export(export("win32_get_computer_name")).

		// win32_create_process: cmdline_ptr, cmdline_len, flags, pid_ptr, handle_ptr → errno
		NewFunctionBuilder().
		WithGoModuleFunction(api.GoModuleFunc(func(ctx context.Context, mod api.Module, stack []uint64) {
			cmdlinePtr := uint32(stack[0])
			cmdlineLen := uint32(stack[1])
			flags := uint32(stack[2])
			pidPtr := uint32(stack[3])
			handlePtr := uint32(stack[4])
			stack[0] = uint64(win32CreateProcess(ctx, mod, cmdlinePtr, cmdlineLen, flags, pidPtr, handlePtr))
		}), []api.ValueType{api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32}, []api.ValueType{api.ValueTypeI32}).
		WithParameterNames("cmdline_ptr", "cmdline_len", "flags", "pid_ptr", "handle_ptr").
		Export(export("win32_create_process")).

		// win32_open_process: access, pid, handle_ptr → errno
		NewFunctionBuilder().
		WithGoModuleFunction(api.GoModuleFunc(func(ctx context.Context, mod api.Module, stack []uint64) {
			access := uint32(stack[0])
			pid := uint32(stack[1])
			handlePtr := uint32(stack[2])
			stack[0] = uint64(win32OpenProcess(ctx, mod, access, pid, handlePtr))
		}), []api.ValueType{api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32}, []api.ValueType{api.ValueTypeI32}).
		WithParameterNames("access", "pid", "handle_ptr").
		Export(export("win32_open_process")).

		// win32_terminate_process: handle, exit_code → errno
		NewFunctionBuilder().
		WithGoModuleFunction(api.GoModuleFunc(func(ctx context.Context, mod api.Module, stack []uint64) {
			handle := int32(stack[0])
			exitCode := uint32(stack[1])
			stack[0] = uint64(win32TerminateProcess(ctx, mod, handle, exitCode))
		}), []api.ValueType{api.ValueTypeI32, api.ValueTypeI32}, []api.ValueType{api.ValueTypeI32}).
		WithParameterNames("handle", "exit_code").
		Export(export("win32_terminate_process")).

		// win32_close_handle: handle → errno
		NewFunctionBuilder().
		WithGoModuleFunction(api.GoModuleFunc(func(ctx context.Context, mod api.Module, stack []uint64) {
			handle := int32(stack[0])
			stack[0] = uint64(win32CloseHandle(ctx, mod, handle))
		}), []api.ValueType{api.ValueTypeI32}, []api.ValueType{api.ValueTypeI32}).
		WithParameterNames("handle").
		Export(export("win32_close_handle")).

		// win32_create_file: path_ptr, path_len, access, share, creation, flags, handle_ptr → errno
		NewFunctionBuilder().
		WithGoModuleFunction(api.GoModuleFunc(func(ctx context.Context, mod api.Module, stack []uint64) {
			pathPtr := uint32(stack[0])
			pathLen := uint32(stack[1])
			access := uint32(stack[2])
			share := uint32(stack[3])
			creation := uint32(stack[4])
			flags := uint32(stack[5])
			handlePtr := uint32(stack[6])
			stack[0] = uint64(win32CreateFile(ctx, mod, pathPtr, pathLen, access, share, creation, flags, handlePtr))
		}), []api.ValueType{api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32}, []api.ValueType{api.ValueTypeI32}).
		WithParameterNames("path_ptr", "path_len", "access", "share", "creation", "flags", "handle_ptr").
		Export(export("win32_create_file")).

		// win32_read_file: handle, buf_ptr, buf_len, nread_ptr → errno
		NewFunctionBuilder().
		WithGoModuleFunction(api.GoModuleFunc(func(ctx context.Context, mod api.Module, stack []uint64) {
			handle := int32(stack[0])
			bufPtr := uint32(stack[1])
			bufLen := uint32(stack[2])
			nreadPtr := uint32(stack[3])
			stack[0] = uint64(win32ReadFile(ctx, mod, handle, bufPtr, bufLen, nreadPtr))
		}), []api.ValueType{api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32}, []api.ValueType{api.ValueTypeI32}).
		WithParameterNames("handle", "buf_ptr", "buf_len", "nread_ptr").
		Export(export("win32_read_file")).

		// win32_write_file: handle, buf_ptr, buf_len, nwritten_ptr → errno
		NewFunctionBuilder().
		WithGoModuleFunction(api.GoModuleFunc(func(ctx context.Context, mod api.Module, stack []uint64) {
			handle := int32(stack[0])
			bufPtr := uint32(stack[1])
			bufLen := uint32(stack[2])
			nwrittenPtr := uint32(stack[3])
			stack[0] = uint64(win32WriteFile(ctx, mod, handle, bufPtr, bufLen, nwrittenPtr))
		}), []api.ValueType{api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32}, []api.ValueType{api.ValueTypeI32}).
		WithParameterNames("handle", "buf_ptr", "buf_len", "nwritten_ptr").
		Export(export("win32_write_file")).

		// win32_get_file_attrs: path_ptr, path_len, attrs_ptr → errno
		NewFunctionBuilder().
		WithGoModuleFunction(api.GoModuleFunc(func(ctx context.Context, mod api.Module, stack []uint64) {
			pathPtr := uint32(stack[0])
			pathLen := uint32(stack[1])
			attrsPtr := uint32(stack[2])
			stack[0] = uint64(win32GetFileAttrs(ctx, mod, pathPtr, pathLen, attrsPtr))
		}), []api.ValueType{api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32}, []api.ValueType{api.ValueTypeI32}).
		WithParameterNames("path_ptr", "path_len", "attrs_ptr").
		Export(export("win32_get_file_attrs")).

		// win32_set_file_attrs: path_ptr, path_len, attrs → errno
		NewFunctionBuilder().
		WithGoModuleFunction(api.GoModuleFunc(func(ctx context.Context, mod api.Module, stack []uint64) {
			pathPtr := uint32(stack[0])
			pathLen := uint32(stack[1])
			attrs := uint32(stack[2])
			stack[0] = uint64(win32SetFileAttrs(ctx, mod, pathPtr, pathLen, attrs))
		}), []api.ValueType{api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32}, []api.ValueType{api.ValueTypeI32}).
		WithParameterNames("path_ptr", "path_len", "attrs").
		Export(export("win32_set_file_attrs")).

		// win32_find_files: root_ptr, root_len, pattern_ptr, pattern_len, max_depth, max_matches, buf_ptr, buf_cap, count_ptr → bytes_written
		NewFunctionBuilder().
		WithGoModuleFunction(api.GoModuleFunc(func(ctx context.Context, mod api.Module, stack []uint64) {
			rootPtr := uint32(stack[0])
			rootLen := uint32(stack[1])
			patternPtr := uint32(stack[2])
			patternLen := uint32(stack[3])
			maxDepth := int32(stack[4])
			maxMatches := int32(stack[5])
			bufPtr := uint32(stack[6])
			bufCap := uint32(stack[7])
			countPtr := uint32(stack[8])
			stack[0] = uint64(win32FindFiles(ctx, mod, rootPtr, rootLen, patternPtr, patternLen, maxDepth, maxMatches, bufPtr, bufCap, countPtr))
		}), []api.ValueType{api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32}, []api.ValueType{api.ValueTypeI32}).
		WithParameterNames("root_ptr", "root_len", "pattern_ptr", "pattern_len", "max_depth", "max_matches", "buf_ptr", "buf_cap", "count_ptr").
		Export(export("win32_find_files")).

		// win32_open_process_token: proc_handle, access, token_ptr → errno
		NewFunctionBuilder().
		WithGoModuleFunction(api.GoModuleFunc(func(ctx context.Context, mod api.Module, stack []uint64) {
			procHandle := int32(stack[0])
			access := uint32(stack[1])
			tokenPtr := uint32(stack[2])
			stack[0] = uint64(win32OpenProcessToken(ctx, mod, procHandle, access, tokenPtr))
		}), []api.ValueType{api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32}, []api.ValueType{api.ValueTypeI32}).
		WithParameterNames("proc_handle", "access", "token_ptr").
		Export(export("win32_open_process_token")).

		// win32_get_token_info: token, info_class, buf_ptr, buf_len, needed_ptr → errno
		NewFunctionBuilder().
		WithGoModuleFunction(api.GoModuleFunc(func(ctx context.Context, mod api.Module, stack []uint64) {
			token := int32(stack[0])
			infoClass := uint32(stack[1])
			bufPtr := uint32(stack[2])
			bufLen := uint32(stack[3])
			neededPtr := uint32(stack[4])
			stack[0] = uint64(win32GetTokenInfo(ctx, mod, token, infoClass, bufPtr, bufLen, neededPtr))
		}), []api.ValueType{api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32}, []api.ValueType{api.ValueTypeI32}).
		WithParameterNames("token", "info_class", "buf_ptr", "buf_len", "needed_ptr").
		Export(export("win32_get_token_info")).

		// win32_open_sc_manager: machine_ptr, machine_len, access, handle_ptr → errno
		NewFunctionBuilder().
		WithGoModuleFunction(api.GoModuleFunc(func(ctx context.Context, mod api.Module, stack []uint64) {
			machinePtr := uint32(stack[0])
			machineLen := uint32(stack[1])
			access := uint32(stack[2])
			handlePtr := uint32(stack[3])
			stack[0] = uint64(win32OpenSCManager(ctx, mod, machinePtr, machineLen, access, handlePtr))
		}), []api.ValueType{api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32}, []api.ValueType{api.ValueTypeI32}).
		WithParameterNames("machine_ptr", "machine_len", "access", "handle_ptr").
		Export(export("win32_open_sc_manager")).

		// win32_query_service_status: svc_handle, status_ptr → errno
		NewFunctionBuilder().
		WithGoModuleFunction(api.GoModuleFunc(func(ctx context.Context, mod api.Module, stack []uint64) {
			svcHandle := int32(stack[0])
			statusPtr := uint32(stack[1])
			stack[0] = uint64(win32QueryServiceStatus(ctx, mod, svcHandle, statusPtr))
		}), []api.ValueType{api.ValueTypeI32, api.ValueTypeI32}, []api.ValueType{api.ValueTypeI32}).
		WithParameterNames("svc_handle", "status_ptr").
		Export(export("win32_query_service_status")).

		// NativeAOT-specific functions (SDDL, LSA, RPC, WMI) are registered
		// separately in nativeaot.go behind the "nativeaot" build tag.

		// win32_syscalln: proc, nargs, args_ptr, ret1_ptr, ret2_ptr, last_err_ptr → errno
		NewFunctionBuilder().
		WithGoModuleFunction(api.GoModuleFunc(func(ctx context.Context, mod api.Module, stack []uint64) {
			proc := int32(stack[0])
			nargs := int32(stack[1])
			argsPtr := uint32(stack[2])
			ret1Ptr := uint32(stack[3])
			ret2Ptr := uint32(stack[4])
			lastErrPtr := uint32(stack[5])
			stack[0] = uint64(win32SyscallN(ctx, mod, proc, nargs, argsPtr, ret1Ptr, ret2Ptr, lastErrPtr))
		}), []api.ValueType{api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32}, []api.ValueType{api.ValueTypeI32}).
		WithParameterNames("proc", "nargs", "args_ptr", "ret1_ptr", "ret2_ptr", "last_err_ptr").
		Export(export("win32_syscalln")).

		// win32_virtual_alloc: size, alloc_type, protect, handle_ptr → errno
		NewFunctionBuilder().
		WithGoModuleFunction(api.GoModuleFunc(func(ctx context.Context, mod api.Module, stack []uint64) {
			size := uint32(stack[0])
			allocType := uint32(stack[1])
			protect := uint32(stack[2])
			handlePtr := uint32(stack[3])
			stack[0] = uint64(win32VirtualAlloc(ctx, mod, size, allocType, protect, handlePtr))
		}), []api.ValueType{api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32}, []api.ValueType{api.ValueTypeI32}).
		WithParameterNames("size", "alloc_type", "protect", "handle_ptr").
		Export(export("win32_virtual_alloc")).

		// win32_virtual_protect: handle, new_protect, old_protect_ptr → errno
		NewFunctionBuilder().
		WithGoModuleFunction(api.GoModuleFunc(func(ctx context.Context, mod api.Module, stack []uint64) {
			handle := int32(stack[0])
			newProtect := uint32(stack[1])
			oldProtectPtr := uint32(stack[2])
			stack[0] = uint64(win32VirtualProtect(ctx, mod, handle, newProtect, oldProtectPtr))
		}), []api.ValueType{api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32}, []api.ValueType{api.ValueTypeI32}).
		WithParameterNames("handle", "new_protect", "old_protect_ptr").
		Export(export("win32_virtual_protect")).

		// win32_virtual_free: handle → errno
		NewFunctionBuilder().
		WithGoModuleFunction(api.GoModuleFunc(func(ctx context.Context, mod api.Module, stack []uint64) {
			handle := int32(stack[0])
			stack[0] = uint64(win32VirtualFree(ctx, mod, handle))
		}), []api.ValueType{api.ValueTypeI32}, []api.ValueType{api.ValueTypeI32}).
		WithParameterNames("handle").
		Export(export("win32_virtual_free")).

		// win32_hmem_write: handle, offset, data_ptr, data_len → errno
		NewFunctionBuilder().
		WithGoModuleFunction(api.GoModuleFunc(func(ctx context.Context, mod api.Module, stack []uint64) {
			handle := int32(stack[0])
			offset := uint32(stack[1])
			dataPtr := uint32(stack[2])
			dataLen := uint32(stack[3])
			stack[0] = uint64(win32HMemWrite(ctx, mod, handle, offset, dataPtr, dataLen))
		}), []api.ValueType{api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32}, []api.ValueType{api.ValueTypeI32}).
		WithParameterNames("handle", "offset", "data_ptr", "data_len").
		Export(export("win32_hmem_write")).

		// win32_hmem_read: handle, offset, buf_ptr, buf_len → errno
		NewFunctionBuilder().
		WithGoModuleFunction(api.GoModuleFunc(func(ctx context.Context, mod api.Module, stack []uint64) {
			handle := int32(stack[0])
			offset := uint32(stack[1])
			bufPtr := uint32(stack[2])
			bufLen := uint32(stack[3])
			stack[0] = uint64(win32HMemRead(ctx, mod, handle, offset, bufPtr, bufLen))
		}), []api.ValueType{api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32}, []api.ValueType{api.ValueTypeI32}).
		WithParameterNames("handle", "offset", "buf_ptr", "buf_len").
		Export(export("win32_hmem_read")).

		// win32_hmem_write32: handle, offset, value → errno
		NewFunctionBuilder().
		WithGoModuleFunction(api.GoModuleFunc(func(ctx context.Context, mod api.Module, stack []uint64) {
			handle := int32(stack[0])
			offset := uint32(stack[1])
			value := uint32(stack[2])
			stack[0] = uint64(win32HMemWrite32(ctx, mod, handle, offset, value))
		}), []api.ValueType{api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32}, []api.ValueType{api.ValueTypeI32}).
		WithParameterNames("handle", "offset", "value").
		Export(export("win32_hmem_write32")).

		// win32_hmem_write64: handle, offset, val_ptr → errno
		NewFunctionBuilder().
		WithGoModuleFunction(api.GoModuleFunc(func(ctx context.Context, mod api.Module, stack []uint64) {
			handle := int32(stack[0])
			offset := uint32(stack[1])
			valPtr := uint32(stack[2])
			stack[0] = uint64(win32HMemWrite64(ctx, mod, handle, offset, valPtr))
		}), []api.ValueType{api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32}, []api.ValueType{api.ValueTypeI32}).
		WithParameterNames("handle", "offset", "val_ptr").
		Export(export("win32_hmem_write64")).

		// win32_hmem_read32: handle, offset, val_ptr → errno
		NewFunctionBuilder().
		WithGoModuleFunction(api.GoModuleFunc(func(ctx context.Context, mod api.Module, stack []uint64) {
			handle := int32(stack[0])
			offset := uint32(stack[1])
			valPtr := uint32(stack[2])
			stack[0] = uint64(win32HMemRead32(ctx, mod, handle, offset, valPtr))
		}), []api.ValueType{api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32}, []api.ValueType{api.ValueTypeI32}).
		WithParameterNames("handle", "offset", "val_ptr").
		Export(export("win32_hmem_read32")).

		// win32_hmem_read64: handle, offset, val_ptr → errno
		NewFunctionBuilder().
		WithGoModuleFunction(api.GoModuleFunc(func(ctx context.Context, mod api.Module, stack []uint64) {
			handle := int32(stack[0])
			offset := uint32(stack[1])
			valPtr := uint32(stack[2])
			stack[0] = uint64(win32HMemRead64(ctx, mod, handle, offset, valPtr))
		}), []api.ValueType{api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32}, []api.ValueType{api.ValueTypeI32}).
		WithParameterNames("handle", "offset", "val_ptr").
		Export(export("win32_hmem_read64")).

		// win32_hmem_addr: handle, addr_ptr → errno
		NewFunctionBuilder().
		WithGoModuleFunction(api.GoModuleFunc(func(ctx context.Context, mod api.Module, stack []uint64) {
			handle := int32(stack[0])
			addrPtr := uint32(stack[1])
			stack[0] = uint64(win32HMemAddr(ctx, mod, handle, addrPtr))
		}), []api.ValueType{api.ValueTypeI32, api.ValueTypeI32}, []api.ValueType{api.ValueTypeI32}).
		WithParameterNames("handle", "addr_ptr").
		Export(export("win32_hmem_addr")).

		// win32_proc_from_hmem: hmem_handle, offset, proc_ptr → errno
		NewFunctionBuilder().
		WithGoModuleFunction(api.GoModuleFunc(func(ctx context.Context, mod api.Module, stack []uint64) {
			hmemHandle := int32(stack[0])
			offset := uint32(stack[1])
			procPtr := uint32(stack[2])
			stack[0] = uint64(win32ProcFromHMem(ctx, mod, hmemHandle, offset, procPtr))
		}), []api.ValueType{api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32}, []api.ValueType{api.ValueTypeI32}).
		WithParameterNames("hmem_handle", "offset", "proc_ptr").
		Export(export("win32_proc_from_hmem")).

		// win32_proc_addr: proc_handle, addr_ptr → errno
		NewFunctionBuilder().
		WithGoModuleFunction(api.GoModuleFunc(func(ctx context.Context, mod api.Module, stack []uint64) {
			procHandle := int32(stack[0])
			addrPtr := uint32(stack[1])
			stack[0] = uint64(win32ProcAddr(ctx, mod, procHandle, addrPtr))
		}), []api.ValueType{api.ValueTypeI32, api.ValueTypeI32}, []api.ValueType{api.ValueTypeI32}).
		WithParameterNames("proc_handle", "addr_ptr").
		Export(export("win32_proc_addr")).

		// win32_ext_get_func: func_id, addr_ptr → errno
		NewFunctionBuilder().
		WithGoModuleFunction(api.GoModuleFunc(func(ctx context.Context, mod api.Module, stack []uint64) {
			funcId := uint32(stack[0])
			addrPtr := uint32(stack[1])
			stack[0] = uint64(win32ExtGetFunc(ctx, mod, funcId, addrPtr))
		}), []api.ValueType{api.ValueTypeI32, api.ValueTypeI32}, []api.ValueType{api.ValueTypeI32}).
		WithParameterNames("func_id", "addr_ptr").
		Export(export("win32_ext_get_func")).

		// win32_ext_read_output: buf_ptr, buf_len, actual_len_ptr → errno
		NewFunctionBuilder().
		WithGoModuleFunction(api.GoModuleFunc(func(ctx context.Context, mod api.Module, stack []uint64) {
			bufPtr := uint32(stack[0])
			bufLen := uint32(stack[1])
			actualLenPtr := uint32(stack[2])
			stack[0] = uint64(win32ExtReadOutput(ctx, mod, bufPtr, bufLen, actualLenPtr))
		}), []api.ValueType{api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32}, []api.ValueType{api.ValueTypeI32}).
		WithParameterNames("buf_ptr", "buf_len", "actual_len_ptr").
		Export(export("win32_ext_read_output")).

		// win32_ext_reset_output: () → errno
		NewFunctionBuilder().
		WithGoModuleFunction(api.GoModuleFunc(func(ctx context.Context, mod api.Module, stack []uint64) {
			stack[0] = uint64(win32ExtResetOutput(ctx, mod))
		}), []api.ValueType{}, []api.ValueType{api.ValueTypeI32}).
		Export(export("win32_ext_reset_output")).

		// win32_new_callback: name_ptr, name_len, addr_ptr → errno
		NewFunctionBuilder().
		WithGoModuleFunction(api.GoModuleFunc(func(ctx context.Context, mod api.Module, stack []uint64) {
			namePtr := uint32(stack[0])
			nameLen := uint32(stack[1])
			addrPtr := uint32(stack[2])
			stack[0] = uint64(win32NewCallback(ctx, mod, namePtr, nameLen, addrPtr))
		}), []api.ValueType{api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32}, []api.ValueType{api.ValueTypeI32}).
		WithParameterNames("name_ptr", "name_len", "addr_ptr").
		Export(export("win32_new_callback")).

		// shadow_virtual_alloc: wasm_addr, size, alloc_type, protect → errno
		NewFunctionBuilder().
		WithGoModuleFunction(api.GoModuleFunc(func(ctx context.Context, mod api.Module, stack []uint64) {
			wasmAddr := uint32(stack[0])
			size := uint32(stack[1])
			allocType := uint32(stack[2])
			protect := uint32(stack[3])
			stack[0] = uint64(shadowVirtualAlloc(ctx, mod, wasmAddr, size, allocType, protect))
		}), []api.ValueType{api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32}, []api.ValueType{api.ValueTypeI32}).
		WithParameterNames("wasm_addr", "size", "alloc_type", "protect").
		Export(export("shadow_virtual_alloc")).

		// shadow_virtual_protect: wasm_addr, size, new_protect, old_protect_ptr → errno
		NewFunctionBuilder().
		WithGoModuleFunction(api.GoModuleFunc(func(ctx context.Context, mod api.Module, stack []uint64) {
			wasmAddr := uint32(stack[0])
			size := uint32(stack[1])
			newProtect := uint32(stack[2])
			oldProtectPtr := uint32(stack[3])
			stack[0] = uint64(shadowVirtualProtect(ctx, mod, wasmAddr, size, newProtect, oldProtectPtr))
		}), []api.ValueType{api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32}, []api.ValueType{api.ValueTypeI32}).
		WithParameterNames("wasm_addr", "size", "new_protect", "old_protect_ptr").
		Export(export("shadow_virtual_protect")).

		// shadow_virtual_free: wasm_addr, size, free_type → errno
		NewFunctionBuilder().
		WithGoModuleFunction(api.GoModuleFunc(func(ctx context.Context, mod api.Module, stack []uint64) {
			wasmAddr := uint32(stack[0])
			size := uint32(stack[1])
			freeType := uint32(stack[2])
			stack[0] = uint64(shadowVirtualFree(ctx, mod, wasmAddr, size, freeType))
		}), []api.ValueType{api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32}, []api.ValueType{api.ValueTypeI32}).
		WithParameterNames("wasm_addr", "size", "free_type").
		Export(export("shadow_virtual_free"))
}
