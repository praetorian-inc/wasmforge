package migrate

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRun_SyntheticProject(t *testing.T) {
	// Create a temp dir with a fake .NET Framework .csproj.
	tmpDir := t.TempDir()

	// Write a minimal Framework-style .csproj.
	frameworkCsproj := `<?xml version="1.0" encoding="utf-8"?>
<Project ToolsVersion="15.0" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
  <PropertyGroup>
    <AssemblyName>TestProject</AssemblyName>
    <RootNamespace>TestProject</RootNamespace>
    <OutputType>Exe</OutputType>
    <TargetFrameworkVersion>v4.7.2</TargetFrameworkVersion>
  </PropertyGroup>
</Project>`
	if err := os.WriteFile(filepath.Join(tmpDir, "TestProject.csproj"), []byte(frameworkCsproj), 0644); err != nil {
		t.Fatal(err)
	}

	// Write a minimal .cs file that the patcher can match.
	if err := os.WriteFile(filepath.Join(tmpDir, "Program.cs"),
		[]byte("using System;\nnamespace TestProject { class Program { static void Main() {} } }"),
		0644); err != nil {
		t.Fatal(err)
	}

	// Create fake helpers directory with the required .cs files.
	helpersDir := t.TempDir()
	for _, name := range helperNames {
		if err := os.WriteFile(filepath.Join(helpersDir, name), []byte("// "+name), 0644); err != nil {
			t.Fatal(err)
		}
	}

	// Create fake stubs directory with the required stub projects.
	stubsDir := t.TempDir()
	for _, name := range stubDirNames {
		dir := filepath.Join(stubsDir, name)
		if err := os.MkdirAll(dir, 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, name+".csproj"), []byte("<Project></Project>"), 0644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "Stubs.cs"), []byte("// stub"), 0644); err != nil {
			t.Fatal(err)
		}
	}

	// Create fake bridge directory with the required C source files.
	bridgeDir := t.TempDir()
	for _, name := range []string{"wf_bridge.c", "wf_bridge.h", "pinvoke_nativeaot.c"} {
		if err := os.WriteFile(filepath.Join(bridgeDir, name), []byte("// "+name), 0644); err != nil {
			t.Fatal(err)
		}
	}

	result, err := Run(Config{
		SourceDir:  tmpDir,
		HelpersDir: helpersDir,
		StubsDir:   stubsDir,
		BridgeDir:  bridgeDir,
	})
	if err != nil {
		t.Fatalf("Run() failed: %v", err)
	}

	// Verify backup exists.
	if _, err := os.Stat(result.OriginalCsproj); err != nil {
		t.Errorf("original .csproj backup not found: %v", err)
	}

	// Verify new .csproj exists and contains expected elements.
	data, err := os.ReadFile(result.CsprojPath)
	if err != nil {
		t.Fatalf("reading new .csproj: %v", err)
	}
	content := string(data)

	for _, expected := range []string{
		"net10.0",
		"InvariantGlobalization",
		"RuntimeIdentifier",
		"wasi-wasm",
		"MSBuildEnableWorkloadResolver",
		"NATIVEAOT_WASI",
		"TestProject",
		"Microsoft.DotNet.ILCompiler.LLVM",
		"runtime.linux-x64.Microsoft.DotNet.ILCompiler.LLVM",
		"bridge/wf_bridge.c",
		"bridge/pinvoke_nativeaot.c",
		"DirectPInvoke",
		"kernel32.dll",
		"advapi32.dll",
	} {
		if !strings.Contains(content, expected) {
			t.Errorf(".csproj missing %q", expected)
		}
	}

	// Verify PublishAot is absent (ILCompiler.LLVM handles AOT, PublishAot causes SDK errors).
	if strings.Contains(content, "PublishAot") {
		t.Error(".csproj must not contain PublishAot")
	}

	// Verify helpers injected.
	if len(result.InjectedHelpers) != len(helperNames) {
		t.Errorf("expected %d injected helpers, got %d", len(helperNames), len(result.InjectedHelpers))
	}

	// Verify WasmForge/ subdir exists.
	if _, err := os.Stat(filepath.Join(tmpDir, "WasmForge")); err != nil {
		t.Error("WasmForge/ subdirectory not created")
	}

	// Verify bridge/ directory was copied with expected files.
	for _, name := range []string{"wf_bridge.c", "wf_bridge.h", "pinvoke_nativeaot.c"} {
		if _, err := os.Stat(filepath.Join(tmpDir, "bridge", name)); err != nil {
			t.Errorf("bridge file not copied: %s: %v", name, err)
		}
	}

	// Verify nuget.config was written.
	nugetConfigPath := filepath.Join(tmpDir, "nuget.config")
	nugetData, err := os.ReadFile(nugetConfigPath)
	if err != nil {
		t.Fatalf("nuget.config not written: %v", err)
	}
	nugetContent := string(nugetData)
	if !strings.Contains(nugetContent, "dotnet-experimental") {
		t.Error("nuget.config missing dotnet-experimental feed")
	}
	if !strings.Contains(nugetContent, "pkgs.dev.azure.com/dnceng/public/_packaging/dotnet-experimental") {
		t.Error("nuget.config missing dotnet-experimental feed URL")
	}
	if !strings.Contains(nugetContent, "nuget.org") {
		t.Error("nuget.config missing nuget.org feed")
	}

	// Verify idempotency: running again must not return an error.
	_, err = Run(Config{
		SourceDir:  tmpDir,
		HelpersDir: helpersDir,
		StubsDir:   stubsDir,
		BridgeDir:  bridgeDir,
	})
	if err != nil {
		t.Fatalf("Run() idempotency check failed: %v", err)
	}

	// Verify nuget.config is not overwritten on second run (idempotent).
	nugetData2, err := os.ReadFile(nugetConfigPath)
	if err != nil {
		t.Fatalf("nuget.config disappeared after second run: %v", err)
	}
	if string(nugetData2) != nugetContent {
		t.Error("nuget.config was overwritten on second run (should be idempotent)")
	}
}

func TestGenerateCsproj(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.csproj")
	err := GenerateCsproj(path, CsprojData{
		ProjectName:     "Seatbelt",
		TargetFramework: "net10.0",
		AllowUnsafe:     true,
		NuGetPackages:   DefaultNuGetPackages(),
		StubProjects: []string{
			"stubs/System.DirectoryServices/System.DirectoryServices.csproj",
		},
	})
	if err != nil {
		t.Fatalf("GenerateCsproj: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	content := string(data)

	if !strings.Contains(content, "<AssemblyName>Seatbelt</AssemblyName>") {
		t.Error("missing AssemblyName")
	}
	if !strings.Contains(content, "<AllowUnsafeBlocks>true</AllowUnsafeBlocks>") {
		t.Error("missing AllowUnsafeBlocks")
	}
	if !strings.Contains(content, "System.Security.Cryptography.Pkcs") {
		t.Error("missing NuGet package reference")
	}
	if !strings.Contains(content, "System.DirectoryServices.csproj") {
		t.Error("missing stub project reference")
	}
	if !strings.Contains(content, "Microsoft.DotNet.ILCompiler.LLVM") {
		t.Error("missing NativeAOT-LLVM package reference")
	}
	if !strings.Contains(content, "bridge/wf_bridge.c") {
		t.Error("missing NativeLibrary bridge reference")
	}
	if !strings.Contains(content, "DirectPInvoke") {
		t.Error("missing DirectPInvoke entries")
	}
}

func TestDetectProjectName(t *testing.T) {
	tests := []struct {
		name    string
		content string
		want    string
	}{
		{"assembly_name", `<AssemblyName>Rubeus</AssemblyName>`, "Rubeus"},
		{"root_namespace", `<RootNamespace>Seatbelt</RootNamespace>`, "Seatbelt"},
		{"both_prefers_assembly", `<AssemblyName>Foo</AssemblyName><RootNamespace>Bar</RootNamespace>`, "Foo"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := detectProjectName(tt.content)
			if got != tt.want {
				t.Errorf("detectProjectName() = %q, want %q", got, tt.want)
			}
		})
	}
}
