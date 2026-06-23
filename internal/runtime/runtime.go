package runtime

import (
	"context"
	"crypto/rand"
	"fmt"
	"os"
	"runtime"
	"strings"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
	"github.com/tetratelabs/wazero/experimental"
	"github.com/tetratelabs/wazero/imports/wasi_snapshot_preview1"
	"github.com/tetratelabs/wazero/sys"

	"github.com/praetorian-inc/wasmforge/internal/hostmod"
)

// Run executes a WASM module with full networking support.
func Run(ctx context.Context, cfg *Config) error {
	if len(cfg.WASMData) == 0 {
		return fmt.Errorf("no WASM data provided")
	}

	// Create wazero runtime with compiler mode for performance.
	rtCfg := wazero.NewRuntimeConfig().
		WithCompilationCache(wazero.NewCompilationCache())
	rt := wazero.NewRuntimeWithConfig(ctx, rtCfg)
	defer rt.Close(ctx)

	// Create socket FD table and pipe table.
	fdTable := hostmod.NewFDTable()
	pipeTable := hostmod.NewPipeTable()

	// Set up context with FD table, pipe table, and config.
	ctx = hostmod.WithFDTable(ctx, fdTable)
	ctx = hostmod.WithPipeTable(ctx, pipeTable)
	ctx = hostmod.WithConfig(ctx, &hostmod.Config{
		RawSockets: cfg.RawSockets,
		Win32APIs:  cfg.Win32APIs,
		DarwinAPIs: cfg.DarwinAPIs,
		Verbose:    os.Getenv("WASMFORGE_VERBOSE") == "1",
	})

	// Create handle table for Darwin framework APIs (simpler than Win32 — no shadow/mirror).
	if cfg.DarwinAPIs {
		ctx = hostmod.WithWin32Handles(ctx)
	}

	// Create Win32 handle table, shadow map, and mirror table if Win32 APIs are enabled.
	if cfg.Win32APIs {
		if !cfg.DarwinAPIs { // DarwinAPIs already created the shared handle table
			ctx = hostmod.WithWin32Handles(ctx)
		}
		ctx = hostmod.WithShadowMap(ctx)
		ctx = hostmod.WithMirrorTable(ctx, hostmod.NewMirrorTable())

		// Register the memory fault handler for lazy host pointer mirroring.
		// When the WASM guest accesses a pending mirror address (beyond linear
		// memory), the handler grows memory, copies host data on demand, and
		// resumes execution — enabling demand-paged mirroring instead of
		// eager deep-copy at SyscallN time.
		ctx = experimental.WithMemoryFaultHandler(ctx, func(mod api.Module, addr, size uint32) bool {
			mt := hostmod.GetMirrorTable(ctx)
			if mt == nil {
				return false
			}
			return mt.HandleFault(mod, addr, size)
		})
	}

	// Patch AMSI before WASM execution. Must happen after LoadLibraryA/amsi.dll
	// is available but before any CLR Assembly.Load(byte[]) in the WASM guest.
	if cfg.Win32APIs && !cfg.NoAMSIPatch {
		hostmod.PatchAMSI()
	}

	// Register WASI preview 1 (filesystem, clock, env, etc.) plus the
	// adapter_close_badfd function that NativeAOT-LLVM compiled modules
	// import from the wasi_snapshot_preview1 namespace. The standard P1
	// spec does not include this function, so we add it via the builder API.
	wasiBuilder := rt.NewHostModuleBuilder(wasi_snapshot_preview1.ModuleName)
	wasi_snapshot_preview1.NewFunctionExporter().ExportFunctions(wasiBuilder)
	wasiBuilder.NewFunctionBuilder().
		WithGoModuleFunction(api.GoModuleFunc(func(_ context.Context, _ api.Module, stack []uint64) {
			// adapter_close_badfd: (i32) → i32
			// Called by NativeAOT adapters when closing a bad FD. Return EBADF (8).
			stack[0] = 8 // WASI EBADF
		}), []api.ValueType{api.ValueTypeI32}, []api.ValueType{api.ValueTypeI32}).
		Export("adapter_close_badfd")
	wasiBuilder.NewFunctionBuilder().
		WithGoModuleFunction(api.GoModuleFunc(func(_ context.Context, _ api.Module, stack []uint64) {
			// adapter_open_badfd: (i32) → i32
			// Called by NativeAOT adapters to open a placeholder FD.
			// Input is fd flags, return EBADF (8).
			stack[0] = 8 // WASI EBADF
		}), []api.ValueType{api.ValueTypeI32}, []api.ValueType{api.ValueTypeI32}).
		Export("adapter_open_badfd")
	// Override sched_yield to actually yield the Go scheduler.
	// NativeAOT-WASI modules need real scheduling points for:
	// 1. GC to run (NativeAOT GC is single-threaded in WASM, needs host yields)
	// 2. Cooperative yield protocol (errnoYIELD retry loops)
	// 3. Preventing memory pressure buildup during P/Invoke-heavy operations
	// The default wazero implementation is a no-op (FakeOsyield).
	wasiBuilder.NewFunctionBuilder().
		WithGoModuleFunction(api.GoModuleFunc(func(_ context.Context, _ api.Module, stack []uint64) {
			runtime.Gosched()
			stack[0] = 0 // errno = 0 (success)
		}), []api.ValueType{}, []api.ValueType{api.ValueTypeI32}).
		Export("sched_yield")
	if _, err := wasiBuilder.Instantiate(ctx); err != nil {
		return fmt.Errorf("instantiating wasi_snapshot_preview1: %w", err)
	}

	// Register WASI P2 stub modules for NativeAOT-LLVM compiled modules.
	// cfg.Args is the user-facing argv (including argv[0]); pass it through so
	// wasi:cli/environment.get-arguments returns the real args, not a stub.
	if err := registerWASIP2Stubs(ctx, rt, cfg.Args); err != nil {
		return fmt.Errorf("registering WASI P2 stubs: %w", err)
	}

	// Register host module (sockets, DNS, raw, Win32).
	if _, err := hostmod.Register(rt).Instantiate(ctx); err != nil {
		return fmt.Errorf("instantiating host module: %w", err)
	}

	// Configure WASI.
	fsCfg := wazero.NewFSConfig()

	// Mount directories.
	for _, mount := range cfg.FSMounts {
		hostPath, guestPath := parseFSMount(mount)
		fsCfg = fsCfg.WithDirMount(hostPath, guestPath)
	}

	// Auto-mount host filesystem for transparent file access.
	// On Windows, mount each available drive letter (C: → /c, D: → /d, etc.).
	// On Unix, mount the root filesystem (/ → /).
	if runtime.GOOS == "windows" {
		for _, drive := range "CDEFGHIJKLMNOPQRSTUVWXYZ" {
			drivePath := string(drive) + ":\\"
			if _, err := os.Stat(drivePath); err == nil {
				// Mount at /c (Go WASM convention)
				guestPath := "/" + strings.ToLower(string(drive))
				fsCfg = fsCfg.WithDirMount(drivePath, guestPath)
				// Also mount at C: (NativeAOT-WASI .NET convention —
				// .NET uses Windows-style paths like C:\Users which WASI
				// resolves relative to a preopened "C:" directory)
				fsCfg = fsCfg.WithDirMount(drivePath, string(drive)+":")
			}
		}
	} else {
		fsCfg = fsCfg.WithDirMount("/", "/")
	}

	// Auto-mount /etc for DNS resolution. On Linux, /etc/resolv.conf exists
	// natively. On Windows, we create a synthetic resolv.conf with the
	// system's DNS servers so Go's pure-Go resolver works in WASM.
	if _, err := os.Stat("/etc/resolv.conf"); err == nil {
		fsCfg = fsCfg.WithReadOnlyDirMount("/etc", "/etc")
	} else if synthDir, cleanup := synthResolvConf(); synthDir != "" {
		if cleanup != nil {
			defer cleanup()
		}
		fsCfg = fsCfg.WithReadOnlyDirMount(synthDir, "/etc")
	}

	// Auto-mount /tmp as writable for temp file operations (standard WASI practice).
	if info, err := os.Stat("/tmp"); err == nil && info.IsDir() {
		fsCfg = fsCfg.WithDirMount("/tmp", "/tmp")
	}

	// Configure module.
	modCfg := wazero.NewModuleConfig().
		WithStdout(cfg.Stdout).
		WithStderr(cfg.Stderr).
		WithStdin(cfg.Stdin).
		WithFSConfig(fsCfg).
		WithRandSource(rand.Reader).
		WithSysWalltime().
		WithSysNanotime().
		WithSysNanosleep().
		WithStartFunctions("_start").
		WithName("")

	// Set args.
	if len(cfg.Args) > 0 {
		modCfg = modCfg.WithArgs(cfg.Args...)
	}

	// Set environment variables. Skip entries with empty keys (Windows has
	// drive-specific entries like "=C:=C:\Windows" that start with '=').
	// Override TMPDIR to /tmp since the host's temp dir path (e.g.,
	// /var/folders/... on macOS) may not be mounted in the WASI filesystem.
	tmpOverridden := false
	for _, env := range cfg.Env {
		parts := strings.SplitN(env, "=", 2)
		if len(parts) == 2 && parts[0] != "" {
			if parts[0] == "TMPDIR" || parts[0] == "TMP" || parts[0] == "TEMP" {
				modCfg = modCfg.WithEnv(parts[0], "/tmp")
				tmpOverridden = true
			} else {
				modCfg = modCfg.WithEnv(parts[0], parts[1])
			}
		}
	}
	// Ensure TMPDIR is set even if not in the host environment.
	if !tmpOverridden {
		modCfg = modCfg.WithEnv("TMPDIR", "/tmp")
	}

	// Set COLUMNS so Console.WindowWidth doesn't throw in WASI.
	// CommandLineParser and other tools use this for help text formatting.
	modCfg = modCfg.WithEnv("COLUMNS", "120")

	// Set SSL_CERT_FILE so Go's crypto/x509 can find CA certificates.
	// The wasip1 build may not check platform-specific cert paths,
	// so we explicitly point to the cert file if it exists and wasn't
	// already set in the host environment.
	if os.Getenv("SSL_CERT_FILE") == "" {
		for _, p := range []string{
			"/etc/ssl/cert.pem",                      // macOS, some Linux
			"/etc/ssl/certs/ca-certificates.crt",     // Debian/Ubuntu
			"/etc/pki/tls/certs/ca-bundle.crt",       // RHEL/CentOS
			"/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem", // Fedora
		} {
			if _, err := os.Stat(p); err == nil {
				modCfg = modCfg.WithEnv("SSL_CERT_FILE", p)
				break
			}
		}
	}

	// Lock OS thread for Win32 API mode. COM objects (used by CLR/.NET)
	// require thread affinity — all calls on a COM interface must happen
	// on the same OS thread.
	if cfg.Win32APIs {
		runtime.LockOSThread()
	}

	// Compile WASM module.
	compiled, err := rt.CompileModule(ctx, cfg.WASMData)
	if err != nil {
		return fmt.Errorf("compiling WASM module: %w", err)
	}

	// Instantiate and run.
	_, err = rt.InstantiateModule(ctx, compiled, modCfg)
	if err != nil {
		// Check if this is a normal exit (exit code 0).
		if exitErr, ok := err.(*sys.ExitError); ok {
			fmt.Fprintf(os.Stderr, "[runtime/debug] WASM proc_exit(%d)\n", exitErr.ExitCode())
			os.Stderr.Sync()
			if exitErr.ExitCode() == 0 {
				return nil
			}
			return fmt.Errorf("WASM module exited with code %d", exitErr.ExitCode())
		}
		fmt.Fprintf(os.Stderr, "[runtime/debug] WASM non-exit error: %v\n", err)
		os.Stderr.Sync()
		return fmt.Errorf("running WASM module: %w", err)
	}

	return nil
}

// parseFSMount splits a "hostPath:guestPath" mount spec, handling Windows
// drive letters (e.g., "C:\Temp\managed:/managed" must not split at "C:").
func parseFSMount(mount string) (hostPath, guestPath string) {
	sep := strings.Index(mount, ":")
	// Skip drive letter colon on Windows-style paths (e.g., "C:\...")
	if sep == 1 && len(mount) > 2 && mount[2] == '\\' || sep == 1 && len(mount) > 2 && mount[2] == '/' {
		// First colon is a drive letter; find the next one.
		next := strings.Index(mount[2:], ":")
		if next >= 0 {
			sep = 2 + next
		} else {
			sep = -1
		}
	}
	if sep >= 0 {
		return mount[:sep], mount[sep+1:]
	}
	return mount, mount
}
