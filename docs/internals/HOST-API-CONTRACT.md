# wasmforge Host API Contract

This document is the source of truth for `env.*` imports exposed to WASM.
Adding a new export requires adding a row here with rationale, classified
under one of categories A/B/C below. Category D ("Unjustified") is a CI failure.

The contract is CI-enforced by `internal/hostmod/contract_test.go`.

## Categories

- **A. Foundation primitive** — generic dispatch / memory / handle operations
  that nothing higher up can replicate. Examples: `mod_invoke`, `mem_alloc`,
  `mod_hread`. WASM cannot do these.
- **B. OS proxy** — direct syscall passthrough where the OS API has no
  equivalent representation inside the WASM sandbox. Examples: `sock_open`,
  `fd_open`, `os_hostname`, `darwin_call`. WASM cannot reach the kernel
  on its own.
- **C. Atomic composite (host-thread-affinity)** — a multi-step Win32 dance
  that legitimately needs host thread/process state (SYSTEM impersonation,
  COM STA-thread affinity, or both). Examples: `lsa_kerbop`. Cannot be
  replicated by `wf_call` chains in WASM.
- **D. Unjustified** — should be migrated to WASM via `wf_call`. CI fails
  if anything in this category lands.

---

## NativeAOT-WASI active surface (Rubeus / Seatbelt path)

Functions registered in `internal/hostmod/nativeaot.go` and exercised by
the Rubeus/Seatbelt parity test suite. Probe-verified against Rubeus.wasm.

| Canonical (Go-side) | Anonymized (WASM import) | Category | Rationale |
|---|---|---|---|
| win32_syscalln | mod_invoke | A | Generic wf_call dispatch — foundation |
| win32_load_library | mod_load | A | DLL loading — foundation |
| win32_get_proc_address | mod_resolve | A | Symbol resolution — foundation |
| win32_host_read_bytes | mod_hread | A | Cross-boundary memory read — foundation |
| win32_register_funcptr | mod_regptr | A | Callback infrastructure — foundation |
| win32_lsa_kerberos_op | lsa_kerbop | C | SYSTEM impersonation + COM STA + LSA on same thread; cannot reproduce via wf_call chains in WASM |
| win32_crypto_op | xc_op | C | Generic crypto dispatcher. Runs the iteration loop of MS-PBKDF2 (Windows DPAPI master-key derivation), RFC PBKDF2, HMAC, plain hash, and AES-CBC host-side via BCrypt. The in-bridge alternative (looping `wf_call` per HMAC) costs ~32k wf_calls per master key (~40 min); the dispatcher is one wf_call per derivation. Designed as the **landing pad for future complex/looped crypto** so we don't grow the host export surface per new primitive. Opcode catalog: sha1/sha256/sha512, hmac1/256/512, pbkdf2_1/256/512, mspbkdf2_1/mspbkdf2_512, aescbcdec |
| win32_io_op | xi_op | B | Generic IO dispatcher. Sibling to xc_op for filesystem operations. Replaces the 6-8 wf_call CreateFile+ReadFile+CloseHandle chain in `fs_read_all` (~46ms per file) with a single host trip via Go's `os.ReadFile` (~<1ms per file). Opcode catalog: read, stat, list. Same wire format as xc_op (opcode string + length-prefixed packed byte fields). Future filesystem ops add opcodes, not exports. |
| win32_reg_search | reg_search | C | Host-side BFS walker for SharpDPAPI's `search` verb. Walks the supplied hive enumerating every value and matches against SharpDPAPI's DPAPI provider GUID + 4 base64/hex string signatures. Doing this in WASM costs ~4 wf_calls per visited key × ~500K HKLM keys → exceeds the lab's 5-minute exec timeout. Host-side BFS uses parent-handle propagation at native Win32 speed (`RegOpenKeyEx(parent, child, …)` — no full-path lookup per key) and completes both hives in seconds. Wire format: NUL-separated UTF-8 records, first record is the "Root:" line matching native FindRegistryBlobs |
| win32_dpapi_backupkey | dpapi_bkey | C | Host-side DsGetDcNameW + LsaOpenPolicy + 2× LsaRetrievePrivateData chain for SharpDPAPI's `backupkey` verb. DsGetDcName writes a `DOMAIN_CONTROLLER_INFOW*` (host pointer) to its OUT param; LsaRetrievePrivateData writes a `LSA_UNICODE_STRING*` (host pointer) whose Buffer field is also a host pointer. wasm32 C# would truncate both via Marshal.PtrToStructure on a 32-bit IntPtr → OOB trap. Single wf_call returns the materialised DC FQDN + 16-byte preferred-key GUID + raw key blob; C# assembles the kirbi (PVK wrapping + base64). Wire format: packed (status u32, dc_name length-prefixed, guid length-prefixed, key_blob length-prefixed) |
| win32_x509_match | x509_match | C | Host-side X.509 store walker for SharpDPAPI's `machinetriage` cert-matching path. Native walks `CurrentUser\MY` + `LocalMachine\MY` then for each cert calls `cert.PublicKey.Key.ToXmlString` (System.Security.Cryptography PNS on NativeAOT-WASI) to compare against a private-key XML derived from the decrypted blob. The bridge takes raw big-endian RSA modulus bytes (extracted by manual byte slicing on the C# side — no crypto calls), walks both stores via `CertEnumCertificatesInStore`, parses each cert's SubjectPublicKeyInfo via `crypto/x509`, compares moduli, and on match returns packed metadata (thumbprint, issuer, subject, dates, EKUs, cert DER) for C# to format the multi-line output + PEM-wrap. Wire format: status u32, then on match 7 length-prefixed records |
| win32_virtual_alloc | mem_alloc | A | Host memory allocation — foundation |
| win32_virtual_free | mem_free | A | Host memory free — foundation |
| win32_hmem_read | mem_read | A | Cross-boundary memory read — foundation |
| win32_hmem_write | mem_write | A | Cross-boundary memory write — foundation |
| win32_hmem_write32 | mem_write32 | A | Cross-boundary u32 write — foundation |
| win32_hmem_write64 | mem_write64 | A | Cross-boundary u64 write — foundation |
| win32_hmem_addr | mem_addr | A | Host VA retrieval — foundation |
| win32_wmi_query_restricted | wmi_query_r | C | Atomic WMI query for restricted namespaces (root\SecurityCenter2, ROOT\Subscription) that fire IUnknown auth callbacks during ConnectServer. The host implementation calls CoSetProxyBlanket and runs the entire IWbemServices chain on a COM STA thread so callbacks never cross the WASM FFI boundary. Seatbelt AntiVirus and WMIEventConsumer parity require this; cannot trivially replicate in WASM-side wf_call chains |

---

## Foundation primitives — socket / networking (all targets)

Registered in `internal/hostmod/module.go`, `tcp.go`, `udp.go`, `io.go`,
`dns.go`, `sockopt.go`. Used by all WASM targets (Go and NativeAOT alike).

| Canonical (Go-side) | Anonymized (WASM import) | Category | Rationale |
|---|---|---|---|
| sock_open | fd_open | B | Socket creation — WASM has no kernel socket syscall |
| sock_bind | fd_bind | B | Bind to local address |
| sock_listen | fd_listen | B | Mark socket as listening |
| sock_connect | fd_connect | B | TCP/UDP connect |
| sock_accept | fd_accept | B | Accept incoming connection |
| sock_read | fd_read2 | B | Non-blocking socket read |
| sock_write | fd_write2 | B | Non-blocking socket write |
| sock_close | fd_close2 | B | Socket close |
| sock_sendto | fd_sendto | B | UDP datagrams — sendto |
| sock_recvfrom | fd_recvfrom | B | UDP datagrams — recvfrom |
| sock_shutdown | fd_shutdown | B | Graceful socket shutdown |
| sock_setsockopt | fd_setsockopt | B | Socket option set |
| sock_getsockopt | fd_getsockopt | B | Socket option get |
| sock_getpeername | fd_getpeername | B | Remote address query |
| sock_getsockname | fd_getsockname | B | Local address query |
| sock_getaddrinfo | addr_resolve | B | DNS resolution — WASM has no getaddrinfo |

---

## Foundation primitives — raw sockets (requires --raw-sockets)

Registered in `internal/hostmod/raw.go`.

| Canonical (Go-side) | Anonymized (WASM import) | Category | Rationale |
|---|---|---|---|
| raw_sock_open | fd_raw_open | B | SOCK_RAW creation — requires CAP_NET_RAW, not available in WASM |
| raw_sock_send | fd_raw_send | B | Raw packet send |
| raw_sock_recv | fd_raw_recv | B | Raw packet receive |

---

## Foundation primitives — OS proxies (all targets)

Registered in `internal/hostmod/os_host.go` and `os_exec.go`.

| Canonical (Go-side) | Anonymized (WASM import) | Category | Rationale |
|---|---|---|---|
| os_hostname | sys_hostname | B | gethostname — not available in wasip1 |
| os_getwd | sys_getwd | B | getcwd — WASI path mapping doesn't expose host cwd |
| os_chdir | sys_chdir | B | chdir — host working directory change |
| os_user_current | sys_user | B | getpwuid / GetCurrentUser — not available in WASM |
| os_getpid | sys_pid | B | getpid — WASI has no process ID concept |
| os_process_list | sys_procs | B | Process enumeration — OS-specific, no WASM equivalent |
| os_exec | proc_exec | B | CreateProcess/exec with output capture |
| os_start_process | proc_start | B | Non-blocking process start |
| os_wait4 | proc_wait | B | Wait for child process completion |
| net_interfaces | sys_netifs | B | Network interface enumeration — no WASM equivalent |

---

## Foundation primitives — pipes (all targets)

Registered in `internal/hostmod/pipe.go`.

| Canonical (Go-side) | Anonymized (WASM import) | Category | Rationale |
|---|---|---|---|
| os_pipe | fd_pipe | B | Host pipe pair creation — os.Pipe() returns ENOSYS on wasip1 |
| pipe_read | fd_pread | B | Read from host pipe |
| pipe_write | fd_pwrite | B | Write to host pipe |
| pipe_close | fd_pclose | B | Close host pipe |

---

## --win32-apis Go-side surface (non-NativeAOT)

Functions used by `wasmforge build --win32-apis` with Go source input
(Sliver, goffloader, etc.). Registered via
`internal/hostmod/win32.go`. Not exercised by the Rubeus/Seatbelt parity
tests, but kept for the broader product surface.

### Dispatch / module loading

| Canonical (Go-side) | Anonymized (WASM import) | Category | Rationale |
|---|---|---|---|
| win32_available | mod_available | B | Feature-gate check — thin flag check |
| win32_load_library | mod_load | A | LoadLibraryA — also registered by nativeaot.go |
| win32_get_proc_address | mod_resolve | A | GetProcAddress — also registered by nativeaot.go |
| win32_call | mod_call | B | Call proc (≤6 uint32 args) — thin DLL wrapper for Go programs |
| win32_syscalln | mod_invoke | A | SyscallN (≤15 i64 args) — also registered by nativeaot.go |
| win32_free_library | mod_free | B | FreeLibrary |
| win32_close_handle | mod_close | B | CloseHandle (generic) |
| win32_proc_addr | mod_addr | A | Native address of loaded proc — foundation |
| win32_proc_from_hmem | mem_proc | B | Proc from host memory handle — goffloader pattern |
| win32_register_funcptr | mod_regptr | A | Callback registration — also registered by nativeaot.go |
| win32_host_read_bytes | mod_hread | A | Host memory read — also registered by nativeaot.go |
| win32_new_callback | ext_callback | B | NewCallback (function pointer thunk for Go closures) |

### Registry

| Canonical (Go-side) | Anonymized (WASM import) | Category | Rationale |
|---|---|---|---|
| win32_reg_open_key | win32_reg_open_key | B | RegOpenKeyExW — thin wrapper |
| win32_reg_close_key | win32_reg_close_key | B | RegCloseKey — thin wrapper |
| win32_reg_query_value | reg_query | B | RegQueryValueExW |
| win32_reg_set_value | reg_set | B | RegSetValueExW |
| win32_reg_delete_value | reg_delete | B | RegDeleteValueW |
| win32_reg_enum_key | win32_reg_enum_key | B | RegEnumKeyExW — thin wrapper |

### Filesystem

| Canonical (Go-side) | Anonymized (WASM import) | Category | Rationale |
|---|---|---|---|
| win32_create_file | fs_create | B | CreateFileW |
| win32_read_file | fs_read | B | ReadFile |
| win32_write_file | fs_write | B | WriteFile |
| win32_get_file_attrs | fs_getattr | B | GetFileAttributesW |
| win32_set_file_attrs | fs_setattr | B | SetFileAttributesW |
| win32_find_files | fs_findfiles | B | FindFirstFileW + FindNextFileW enumeration |

### Process

| Canonical (Go-side) | Anonymized (WASM import) | Category | Rationale |
|---|---|---|---|
| win32_get_computer_name | sys_compname | B | GetComputerNameW |
| win32_create_process | proc_create | B | CreateProcessW |
| win32_open_process | proc_open | B | OpenProcess |
| win32_terminate_process | proc_term | B | TerminateProcess |

### Security / tokens

| Canonical (Go-side) | Anonymized (WASM import) | Category | Rationale |
|---|---|---|---|
| win32_open_process_token | sec_opentoken | B | OpenProcessToken |
| win32_get_token_info | sec_tokeninfo | B | GetTokenInformation |
| win32_open_sc_manager | svc_open | B | OpenSCManagerW |
| win32_query_service_status | svc_status | B | QueryServiceStatus |

### Host memory (VirtualAlloc proxy for goffloader/COFF)

| Canonical (Go-side) | Anonymized (WASM import) | Category | Rationale |
|---|---|---|---|
| win32_virtual_alloc | mem_alloc | A | VirtualAlloc on host — also registered by nativeaot.go |
| win32_virtual_protect | mem_protect | B | VirtualProtect — change host memory protection |
| win32_virtual_free | mem_free | A | VirtualFree — also registered by nativeaot.go |
| win32_hmem_write | mem_write | A | WASM→host memory copy — also registered by nativeaot.go |
| win32_hmem_read | mem_read | A | Host→WASM memory copy — also registered by nativeaot.go |
| win32_hmem_write32 | mem_write32 | A | u32 write at host offset — also registered by nativeaot.go |
| win32_hmem_write64 | mem_write64 | A | u64 write at host offset — also registered by nativeaot.go |
| win32_hmem_read32 | mem_read32 | B | u32 read from host offset |
| win32_hmem_read64 | mem_read64 | B | u64 read from host offset |
| win32_hmem_addr | mem_addr | A | Host VA retrieval — also registered by nativeaot.go |
| win32_wmi_query_restricted | wmi_query_r | C | Atomic WMI query for restricted namespaces (root\SecurityCenter2, ROOT\Subscription) that fire IUnknown auth callbacks during ConnectServer. The host implementation calls CoSetProxyBlanket and runs the entire IWbemServices chain on a COM STA thread so callbacks never cross the WASM FFI boundary. Seatbelt AntiVirus and WMIEventConsumer parity require this; cannot trivially replicate in WASM-side wf_call chains |

### Extension API (COFF/BOF callbacks)

| Canonical (Go-side) | Anonymized (WASM import) | Category | Rationale |
|---|---|---|---|
| win32_ext_get_func | ext_getfunc | A | Native address of extension callback — foundation for goffloader |
| win32_ext_read_output | ext_readout | B | Read accumulated extension output |
| win32_ext_reset_output | ext_resetout | B | Clear extension output buffer |

### Shadow memory (VirtualAlloc interception)

| Canonical (Go-side) | Anonymized (WASM import) | Category | Rationale |
|---|---|---|---|
| shadow_virtual_alloc | shm_alloc | A | Shadow VirtualAlloc — intercepts guest allocations for WASM pointer translation |
| shadow_virtual_protect | shm_protect | A | Shadow VirtualProtect — tracks protection changes in shadow map |
| shadow_virtual_free | shm_free | A | Shadow VirtualFree — removes allocation from shadow map |

---

## macOS framework bridge (auto-detected from GOOS=darwin)

Registered in `internal/hostmod/darwin.go`. Only functional on macOS hosts.

| Canonical (Go-side) | Anonymized (WASM import) | Category | Rationale |
|---|---|---|---|
| darwin_available | fw_available | B | Feature-gate check |
| darwin_load | fw_load | B | dlopen — load macOS framework or dylib |
| darwin_get_symbol | fw_sym | B | dlsym — get symbol address |
| darwin_call | fw_call | B | Call C function via assembly trampoline (SysV ABI) with WASM pointer translation |
| darwin_call_masked | fw_call_m | B | Call C function with bitmask-controlled pointer translation |
| darwin_call_raw | fw_call_raw | B | Call C function without pointer translation (remote process addresses) |
| darwin_mem_read | fw_mem_r | B | Read host memory into WASM linear memory |
| darwin_mem_write | fw_mem_w | B | Write WASM data to host memory |
| darwin_callback_create | fw_cb_create | A | Create native callback thunk for WASM closure — foundation for macOS delegate patterns |
| darwin_callback_addr | fw_cb_addr | A | Get native address of callback thunk |
| darwin_callback_wait | fw_cb_wait | A | Block until callback fires (cooperative yield) |
| darwin_callback_return | fw_cb_ret | A | Signal callback completion |
| darwin_callback_free | fw_cb_free | A | Release callback thunk |
| darwin_read_cstring | fw_cstr_r | B | Read null-terminated C string from host memory into WASM |
| darwin_block_create | fw_blk_create | A | Create Objective-C Block literal on host — foundation for ObjC API patterns |
| darwin_block_release | fw_blk_release | A | Release Objective-C Block |
| darwin_block_addr | fw_blk_addr | A | Get native address of Block literal |

---

## Retired / out-of-scope re-migration candidates

These functions appeared in nativeaot.go's earlier registration but were
removed because the C# side migrated to WASM-side wf_call chains:

| Former canonical | Former anonymized | Removed in | Notes |
|---|---|---|---|
| win32_wmi_query | wmi_query | Phase B | WASM-side stub |
| win32_wmi_method | wmi_method | Phase B | WASM-side stub |
| win32_get_sddl | (none) | Phase B | WASM-side via wf_call |
| win32_enum_user_rights | (none) | Phase B | WASM-side stub |
| win32_enum_rpc_endpoints | (none) | Phase B | WASM-side stub |
| win32_enum_network_adapters | (none) | Phase B | WASM-side via wf_call |
| win32_get_file_version_info | (none) | Phase B | WASM-side via wf_call |
| win32_enum_reg_values | (none) | Phase B | WASM-side via wf_call (advapi32) |
| win32_parse_sddl_acl | (none) | Phase B | WASM-side passthrough |
| win32_reg_enum_key (nativeaot path) | (none) | Phase B | WASM-side via wf_call |

If a future feature exercises any of these, the migration follows the Phase 2
pattern: write the WASM-side pinvoke_env_ext.c replacement, remove the
`import_module` attribute in `wf_bridge.h`, retire the Go-side Export.
