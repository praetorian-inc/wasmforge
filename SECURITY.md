# Security Policy

WasmForge is an offensive-security toolchain that compiles Go and .NET programs
to WebAssembly and packages them as polymorphic native binaries. By design,
it produces binaries that resist static analysis and runtime detection by
common AV/EDR products. Please keep this in mind when deciding whether to
file a security report.

## Supported Versions

WasmForge is a pre-1.0 project. Only the current `main` branch is supported.

## Reporting a Vulnerability

Email **security@praetorian.com**. Please include:

- A description of the issue and its impact
- A minimal reproduction (command line, source snippet, sample WASM, etc.)
- Affected commit SHA(s) on `main`
- Whether you intend to disclose publicly, and on what timeline

We will acknowledge your report within 3 business days and aim to respond
substantively within 10 business days. We prefer **coordinated disclosure**
with a 90-day window from the date of acknowledgement; we are happy to
negotiate longer windows for complex issues.

## In Scope

We treat the following as security issues and triage them accordingly:

- **Supply-chain risks** in the build pipeline — anything that lets
  compiling a wasmforge-built binary inject code into the developer's
  host machine beyond the documented `go build`/`dotnet publish` steps.

## Out of Scope

The following are not security issues — they are either intended behavior
or outside the project's threat model:

- **A specific AV / EDR product detects a wasmforge-built binary.**
  Producing detectable binaries is the explicit purpose of the tool;
  improving evasion is a feature backlog item, not a security report.
- **Ghost profile collisions** — a wasmforge binary's `gopclntab`
  resembles a real product (Traefik, Caddy, etc.). The bundled profiles
  are sampled from public binaries; this is intentional.
- **AV detection of guest payloads embedded inside a wasmforge binary.**
  The guest content's signatures (Sliver implants, etc.) are not part
  of the wasmforge attack surface.
- **Defender / SmartScreen reputation gating** of unsigned or
  newly-signed binaries.
- **Vulnerabilities in tooling we depend on** (Go toolchain, .NET SDK,
  WASI SDK, osslsigncode, etc.) that are not introduced or amplified
  by wasmforge. Report those upstream.

## Disclosure

Once a fix lands on `main`, we will credit reporters in the commit
message and/or release notes unless they request otherwise.
