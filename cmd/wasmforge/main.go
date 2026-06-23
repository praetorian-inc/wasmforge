package main

import (
	"fmt"
	"os"
	"os/exec"

	"github.com/spf13/cobra"
	"github.com/praetorian-inc/wasmforge/internal/build"
	"github.com/praetorian-inc/wasmforge/internal/dotnet/migrate"
	"github.com/praetorian-inc/wasmforge/internal/patch"
	"github.com/praetorian-inc/wasmforge/internal/patch/rules"
)

var version = build.Version


func main() {
	root := &cobra.Command{
		Use:   "wasmforge",
		Short: "Go-to-WASM toolchain with full networking",
		Long: `WasmForge compiles standard Go programs to WASM with transparent networking.
Write normal Go code using net.Dial, net.Listen, net/http, and WasmForge
produces a single native binary that sandboxes the code in WASM with real
network I/O.`,
	}

	var (
		output          string
		rawSockets      bool
		win32APIs       bool
		fsMounts        []string
		verbose         bool
		signMode        string
		noSign          bool
		buildTags       string
		ghost           string
		peCompany       string
		peProduct       string
		peDescription   string
		peCopyright     string
		peFileVersion   string
		precompiledWASM string
		noAMSIPatch     bool
	)

	buildCmd := &cobra.Command{
		Use:   "build [project]",
		Short: "Compile a Go or C# project to a WASM-sandboxed native binary",
		Args:  cobra.RangeArgs(0, 1),
		RunE: func(cmd *cobra.Command, args []string) error {
			pkg := ""
			if len(args) > 0 {
				pkg = args[0]
			}
			if pkg == "" && precompiledWASM == "" {
				return fmt.Errorf("either a Go or C# project path or --wasm <path> is required")
			}
			opts := build.Options{
				Package:         pkg,
				Output:          output,
				RawSockets:      rawSockets,
				Win32APIs:       win32APIs,
				FSMounts:        fsMounts,
				Verbose:         verbose,
				SignMode:        signMode,
				NoSign:          noSign,
				BuildTags:       buildTags,
				Ghost:           ghost,
				NoAMSIPatch:     noAMSIPatch,
				// NativeAOT is auto-set inside build.Run() when --wasm or a C# project is detected.
				PrecompiledWASM: precompiledWASM,
				MigrateFunc: func(sourceDir string, v bool) error {
					result, err := migrate.Run(migrate.Config{
						SourceDir: sourceDir,
						Verbose:   v,
					})
					if err != nil {
						return err
					}
					if v {
						fmt.Fprintf(os.Stderr, "wasmforge: migrated %s (%d helpers, %d patches)\n",
							result.CsprojPath, len(result.InjectedHelpers), result.PatchesApplied)
					}
					return nil
				},
				PE: build.PEMetadata{
					CompanyName: peCompany,
					ProductName: peProduct,
					Description: peDescription,
					Copyright:   peCopyright,
					FileVersion: peFileVersion,
				},
			}
			return build.Run(opts)
		},
	}
	buildCmd.Flags().StringVarP(&output, "output", "o", "", "Output binary path")
	buildCmd.Flags().BoolVar(&rawSockets, "raw-sockets", false, "Enable raw socket support (requires privileges)")
	buildCmd.Flags().BoolVar(&win32APIs, "win32-apis", false, "Force Win32 API support on. Auto-enabled for Windows targets; pass explicitly only to enable on non-Windows hosts")
	buildCmd.Flags().StringSliceVar(&fsMounts, "fs-mount", nil, "Mount host directory into WASM (hostpath:guestpath)")
	buildCmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "Verbose output")
	buildCmd.Flags().StringVar(&peCompany, "pe-company", "", "PE VERSIONINFO CompanyName")
	buildCmd.Flags().StringVar(&peProduct, "pe-product", "", "PE VERSIONINFO ProductName")
	buildCmd.Flags().StringVar(&peDescription, "pe-description", "", "PE VERSIONINFO FileDescription")
	buildCmd.Flags().StringVar(&peCopyright, "pe-copyright", "", "PE VERSIONINFO LegalCopyright")
	buildCmd.Flags().StringVar(&peFileVersion, "pe-file-version", "", "PE VERSIONINFO FileVersion (e.g. 10.0.19041.1)")
	buildCmd.Flags().StringVar(&signMode, "sign", "", "Sign binary: 'self' for self-signed, or domain name (e.g., 'google.com') for spoofed cert")
	buildCmd.Flags().BoolVar(&noSign, "no-sign", false, "Disable default auto-signing for Windows targets")
	buildCmd.Flags().StringVar(&buildTags, "tags", "", "Extra Go build tags (comma-separated, e.g. 'shell,ps,netstat')")
	buildCmd.Flags().StringVar(&ghost, "ghost", "", "Ghost profile name for gopclntab camouflage (e.g., 'traefik', 'caddy')")
	buildCmd.Flags().StringVar(&precompiledWASM, "wasm", "", "Use precompiled WASM file instead of compiling Go source")
	buildCmd.Flags().BoolVar(&noAMSIPatch, "no-amsi-patch", false, "Skip AMSI patching at runtime (use for Go payloads to avoid behavioral AMSI-bypass detections)")

	runCmd := &cobra.Command{
		Use:   "run [package]",
		Short: "Build and immediately run a Go package in WASM",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			tmpOut, err := os.CreateTemp("", "wasmforge-run-*")
			if err != nil {
				return fmt.Errorf("creating temp file: %w", err)
			}
			tmpOut.Close()
			defer os.Remove(tmpOut.Name())

			opts := build.Options{
				Package:    args[0],
				Output:     tmpOut.Name(),
				RawSockets: rawSockets,
				Win32APIs:  win32APIs,
				FSMounts:   fsMounts,
				Verbose:    verbose,
			}
			if err := build.Run(opts); err != nil {
				return err
			}

			c := exec.Command(tmpOut.Name(), args[1:]...)
			c.Stdout = os.Stdout
			c.Stderr = os.Stderr
			c.Stdin = os.Stdin
			return c.Run()
		},
	}
	runCmd.Flags().BoolVar(&rawSockets, "raw-sockets", false, "Enable raw socket support")
	runCmd.Flags().BoolVar(&win32APIs, "win32-apis", false, "Force Win32 API support on. Auto-enabled for Windows targets; pass explicitly only to enable on non-Windows hosts")
	runCmd.Flags().StringSliceVar(&fsMounts, "fs-mount", nil, "Mount host directory into WASM")
	runCmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "Verbose output")

	cleanCmd := &cobra.Command{
		Use:   "clean",
		Short: "Remove the patched GOROOT cache",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := build.CleanCache(); err != nil {
				return err
			}
			fmt.Println("wasmforge: cache cleaned")
			return nil
		},
	}

	versionCmd := &cobra.Command{
		Use:   "version",
		Short: "Print wasmforge version",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("wasmforge %s\n", version)
		},
	}

	var astVerify bool
	var useLegacy bool
	dotnetPatchCmd := &cobra.Command{
		Use:   "dotnet-patch <source-dir>",
		Short: "Apply NativeAOT-WASI C# source patches",
		Long: `Apply NativeAOT-WASI C# source patches to the given source directory.

The default path runs the AST patcher (all 241+ rules registered via
AllNativeAOTASTRules) and prints a coverage report showing how many rules
matched. Use --verbose to see per-file rule application.

With --ast-verify, runs both the legacy text patcher and the AST patcher on
separate copies of the source tree, then byte-diffs the results. Use this to
gate incremental AST rule migration in CI.

With --legacy, falls back to the legacy text patcher. Use this as an emergency
rollback if the AST patcher produces incorrect output.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if astVerify {
				return patch.VerifyEquivalence(args[0], rules.AllNativeAOTASTRules(), verbose)
			}
			var count int
			var err error
			if useLegacy {
				count, err = patch.ApplyCSharpPatches(args[0], verbose)
				if err != nil {
					return err
				}
			} else {
				var report *patch.CoverageReport
				count, report, err = patch.ApplyCSharpASTPatches(args[0], rules.AllNativeAOTASTRules(), verbose)
				if err != nil {
					return err
				}
				if report != nil {
					fmt.Println(report)
				}
			}
			// Generate Properties/WfDirectPInvoke.props listing every DLL
			// referenced by [DllImport] across the source tree. The patcher's
			// csproj rule adds the matching <Import>; without this file,
			// NativeAOT-LLVM falls back to lazy P/Invoke resolution which is
			// unsupported on WASM and causes silent runtime failures across
			// ole32/oleaut32/etc.
			propsPath, dlls, perr := patch.EmitDirectPInvokeProps(args[0], verbose)
			if perr != nil {
				return fmt.Errorf("emitting DirectPInvoke props: %w", perr)
			}
			fmt.Printf("wasmforge: applied %d patches, %d DirectPInvoke entries at %s\n", count, len(dlls), propsPath)
			return nil
		},
	}
	dotnetPatchCmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "Verbose output")
	dotnetPatchCmd.Flags().BoolVar(&astVerify, "ast-verify", false, "Run AST patcher and verify byte-equivalence with legacy text patcher")
	dotnetPatchCmd.Flags().BoolVar(&useLegacy, "legacy", false, "Use legacy text patcher instead of AST patcher (emergency rollback)")

	var dotnetMigrateVerbose bool
	dotnetMigrateCmd := &cobra.Command{
		Use:   "dotnet-migrate <source-dir>",
		Short: "Migrate .NET Framework project to .NET 10 NativeAOT-WASI",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			result, err := migrate.Run(migrate.Config{
				SourceDir: args[0],
				Verbose:   dotnetMigrateVerbose,
			})
			if err != nil {
				return err
			}
			fmt.Printf("wasmforge: migrated %s\n", result.CsprojPath)
			fmt.Printf("wasmforge: injected %d helpers\n", len(result.InjectedHelpers))
			fmt.Printf("wasmforge: applied %d patches\n", result.PatchesApplied)
			return nil
		},
	}
	dotnetMigrateCmd.Flags().BoolVarP(&dotnetMigrateVerbose, "verbose", "v", false, "Verbose output")

	root.AddCommand(buildCmd, runCmd, cleanCmd, versionCmd, dotnetPatchCmd, dotnetMigrateCmd)

	if err := root.Execute(); err != nil {
		os.Exit(1)
	}
}
