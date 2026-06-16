package test

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/BurntSushi/toml"
)

// Config holds the full test suite configuration loaded from testconfig.toml.
type Config struct {
	WasmForge WasmForgeConfig `toml:"wasmforge"`
	Remote    RemoteConfig    `toml:"remote"`
	Sliver    SliverConfig    `toml:"sliver"`
	Proxy     ProxyConfig     `toml:"proxy"`
	Dotnet    DotnetConfig    `toml:"dotnet"`
}

type DotnetConfig struct {
	Enabled        bool   `toml:"enabled"`
	LudusWorkDir   string `toml:"ludus_work_dir"`
	SeatbeltSource string `toml:"seatbelt_source"`
	RubeusSource   string `toml:"rubeus_source"`
	SeatbeltRepo   string `toml:"seatbelt_repo"`
	RubeusRepo     string `toml:"rubeus_repo"`
	WasmCacheDir   string `toml:"wasm_cache_dir"`
}

type WasmForgeConfig struct {
	Binary string `toml:"binary"` // Path to pre-built binary; empty = auto-build.
	Source string `toml:"source"` // Path to wasmforge source root.
}

type RemoteConfig struct {
	Enabled bool        `toml:"enabled"`
	Win11   Win11Config `toml:"win11"`
}

type Win11Config struct {
	Machine string `toml:"machine"`
	WorkDir string `toml:"work_dir"`
}

type SliverConfig struct {
	Enabled        bool   `toml:"enabled"`
	ClientBinary   string `toml:"client_binary"` // Path to sliver-client binary; empty = auto-detect from PATH.
	OperatorConfig string `toml:"operator_config"`
	ImplantSource  string `toml:"implant_source"`
	// SeatbeltPath / RubeusPath are wasmforge-wrapped wf-out/*.exe binaries,
	// used by the parity tests (labctl push + run as a process). They do NOT
	// work with sliver's execute-assembly — see Native*Path below.
	SeatbeltPath string `toml:"seatbelt_path"`
	RubeusPath   string `toml:"rubeus_path"`
	// NativeSeatbeltPath / NativeRubeusPath point at stock GhostPack builds
	// (COR20 header set) used by the execute-assembly subtests. Sliver pipes
	// them through Donut → CLR-hosting shellcode in the sacrificial process.
	// Leave empty to skip the execute-assembly subtests.
	NativeSeatbeltPath string `toml:"native_seatbelt_path"`
	NativeRubeusPath   string `toml:"native_rubeus_path"`
}

type ProxyConfig struct {
	Enabled      bool   `toml:"enabled"`
	ChiselSource string `toml:"chisel_source"`
	LigoloSource string `toml:"ligolo_source"`
	TestURL      string `toml:"test_url"`
}

// LoadConfig reads testconfig.toml from the test directory.
// If the file does not exist, returns defaults suitable for local-only testing.
func LoadConfig() (*Config, error) {
	cfg := &Config{
		WasmForge: WasmForgeConfig{
			Source: "../",
		},
		Remote: RemoteConfig{
			Win11: Win11Config{
				Machine: "win11",
				WorkDir: `C:\Temp\wftest`,
			},
		},
		Proxy: ProxyConfig{
			TestURL: "https://httpbin.org/ip",
		},
		Dotnet: DotnetConfig{
			LudusWorkDir: "/tmp/wasmforge-dotnet",
			SeatbeltRepo: "https://github.com/GhostPack/Seatbelt.git",
			RubeusRepo:   "https://github.com/GhostPack/Rubeus.git",
		},
	}

	path := configPath()
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return cfg, nil
		}
		return nil, fmt.Errorf("reading config: %w", err)
	}

	if err := toml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}

	// Expand ~ in paths.
	cfg.WasmForge.Binary = expandHome(cfg.WasmForge.Binary)
	cfg.WasmForge.Source = expandHome(cfg.WasmForge.Source)
	cfg.Sliver.ClientBinary = expandHome(cfg.Sliver.ClientBinary)
	cfg.Sliver.OperatorConfig = expandHome(cfg.Sliver.OperatorConfig)
	cfg.Sliver.ImplantSource = expandHome(cfg.Sliver.ImplantSource)
	cfg.Sliver.SeatbeltPath = expandHome(cfg.Sliver.SeatbeltPath)
	cfg.Sliver.RubeusPath = expandHome(cfg.Sliver.RubeusPath)
	cfg.Sliver.NativeSeatbeltPath = expandHome(cfg.Sliver.NativeSeatbeltPath)
	cfg.Sliver.NativeRubeusPath = expandHome(cfg.Sliver.NativeRubeusPath)
	cfg.Proxy.ChiselSource = expandHome(cfg.Proxy.ChiselSource)
	cfg.Proxy.LigoloSource = expandHome(cfg.Proxy.LigoloSource)
	cfg.Dotnet.SeatbeltSource = expandHome(cfg.Dotnet.SeatbeltSource)
	cfg.Dotnet.RubeusSource = expandHome(cfg.Dotnet.RubeusSource)
	cfg.Dotnet.WasmCacheDir = expandHome(cfg.Dotnet.WasmCacheDir)

	return cfg, nil
}

func configPath() string {
	if p := os.Getenv("WFTEST_CONFIG"); p != "" {
		return p
	}
	return filepath.Join(".", "testconfig.toml")
}

func expandHome(path string) string {
	if strings.HasPrefix(path, "~/") {
		home, err := os.UserHomeDir()
		if err == nil {
			return filepath.Join(home, path[2:])
		}
	}
	return path
}
