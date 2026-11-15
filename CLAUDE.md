# Forge.Security.Jwt.Client – notes for AI sessions working on this repository

This repository holds one NuGet package, Forge.Security.Jwt.Client: client-side JWT authentication for Blazor (Server
and WebAssembly) and other .NET clients: `AuthenticationService`, the `AuthenticationStateProvider`
(`JwtTokenAuthenticationStateProvider`), a refresh hosted service, `TokenizedApiCommunicationService` (HTTP calls with
the token), and the registration (`AddForgeJwtClientAuthenticationCore`, `…AsSingleton`). It is one of the seven
packages of the Forge.Blazor solution (`..\Forge.Blazor.sln`). Read in this order:

1. `README.md`: the user documentation. It is packed into the NuGet package.
2. This file: the rules that must hold in every change.
3. `AI/README.md`: the knowledge base: how the package came about and what was decided (`AI/HISTORY.md`), the design
   (`AI/DESIGN.md`), how it is verified (`AI/VERIFICATION.md`), and what is still open (`AI/OPEN.md`).

## The solution around this repository

- **Two kinds of source control:** the solution folder (`..`) is in TFS (the `Scc*` properties of the projects are
  `SAK`). Each package folder below it, this one included, is a git repository of its own, pushed to
  `https://github.com/JZO001/Forge.Security.Jwt.Client`, with its own `LICENSE` (MIT), `README.md`, `logo.png` and
  knowledge base (`CLAUDE.md`, `AI/`).
- **The seven packages and their project references.** A project reference becomes a package dependency on the
  referenced project's current version (as a minimum) when the package is built.

  | Package | References |
  | --- | --- |
  | `Forge.Security.Jwt.Shared` | – |
  | `Forge.Security.Jwt.Service` | Shared |
  | `Forge.Security.Jwt.Service.Storage.SqlServer` | Shared |
  | `Forge.Security.Jwt.Client` | Shared |
  | `Forge.Security.Jwt.Client.Storage.Browser` | Shared, `Forge.Wasm.BrowserStorages` |
  | `Forge.Wasm.BrowserStorages` | – |
  | `Forge.Wasm.BrowserStorages.NewtonSoft.Json` | `Forge.Wasm.BrowserStorages` |

  This package references `Forge.Security.Jwt.Shared`; `Forge.Security.Jwt.Client.Storage.Browser` provides its browser
  storage and is registered after it (README).
- **Files outside this repository that the build uses:**
  - `..\.Documents\Forge.snk`: the strong-name key, the key pair of `Forge.pfx` (exported on 2026-11-15). It has no
    password: whoever has it can sign as Forge, so it stays out of the git repositories;
  - `..\.Documents\`: where the packages are written (`PackageOutputPath`); the packages of the published versions are
    kept there;
- **Solution-level documents:** `..\.github\copilot-instructions.md` (the code conventions of the solution),
  `..\CODE_REVIEW_REPORT.md` (a code review of the whole solution, 2026-02-03).
- **No automated tests.** `..\Testing.Security.Jwt` is a console harness (`net10.0`) that references the seven projects;
  it is not a test project and is not packed.

## Working with Zoltán

- **Language:** Zoltán Juhász owns the package. Zoltán writes in Hungarian; answer in Hungarian. Code, comments, commit
  messages and every document in this repository are in English.
- **Source control and publishing are Zoltán's:** Zoltán manages the git repositories and the TFS workspace, and
  publishes the NuGet packages. Do not run git or `tf` commands that change anything, and do not publish, unless asked.
- **Working style:**
  - one topic at a time;
  - options with a recommendation;
  - facts checked before they are stated;
  - after a work item, report and stop.
- **Keep the knowledge base current:** when a change, a decision or a verification happens, update `AI/` in the same
  step, so the next session can continue from it. What concerns the other packages of the solution as well goes into
  their knowledge bases too.
- **No reference to the package's consumers:** no name of a product, repository or internal decision of a project that
  uses, or will use, this library, in the code, the documents or this knowledge base. Describe a consumer generically
  ("a Blazor WebAssembly application", "a server application"). Allowed:
  - the other `Forge.*` projects (the READMEs point to the `Forge.Yoda` sample solution);
  - the libraries and tools this package uses or documents: Microsoft.JSInterop, Microsoft.Extensions.Http, ASP.NET Core
    Blazor, the `Microsoft.Extensions.*` libraries.

## Invariants (do not break)

1. **The public API is a contract.** The package is published and has consumers.
   - A new parameter is optional, and its default keeps the earlier behaviour.
   - In async methods the `CancellationToken` stays the last parameter.
   - A change that breaks a caller (a removed member, a changed signature or default) raises at least the minor version,
     and the commit message says what breaks under "Compatibility".
   - Dropping a target is such a change for the consumers on it (2026-11-15: `net6.0` and `net7.0`, a minor version).
2. **Dependencies per target.** The targets are `netstandard2.0`, `net8.0`, `net9.0`, `net10.0`, `net11.0`. Each .NET
   target references `Microsoft.JSInterop` and `Microsoft.Extensions.Http` of its own major version; `netstandard2.0`
   the 3.1.32 ones. The table is in `AI/DESIGN.md`; keep it current.
   - A .NET target references the packages of its own major version, so the package does not force a newer framework
     package on a consumer than its framework's own.
   - Do not add a package without asking.
   - A new target (`net12.0` …) gets the references of its major version, unless its shared framework provides the
     assembly; check the ref pack (`packs/Microsoft.NETCore.App.Ref/<version>/ref`). In .NET 11 the
     `Microsoft.Extensions.*.Abstractions` (DependencyInjection, Logging, Options, Hosting, Configuration, Caching …)
     are part of `Microsoft.NETCore.App`; `Microsoft.JSInterop`, `Microsoft.Extensions.Http`, `Microsoft.AspNetCore.*`
     and EF Core are not (checked in the 11.0.0 ref pack on 2026-11-15).
3. **One source for every target.** `netstandard2.0` compiles with C# 7.3 (no `LangVersion` is set) without nullable;
   the .NET targets have `Nullable` on. A nullable annotation is written as `#if NETSTANDARD2_0` / `#else` / `?` /
   `#endif` around the `?`, as in the existing code; other target-specific code sits behind `#if NETSTANDARD2_0` as
   well.
4. **Strong-named.** The assembly is signed with `Forge.snk`, the key pair of `Forge.pfx`; the public key (token
   `97960309cfe8d317`) is part of the identity consumers bind to. Do not change, replace or drop the key without asking.

## Conventions

- **Code style** (from the code and `..\.github\copilot-instructions.md`):
  - block-scoped namespaces (`netstandard2.0` compiles with C# 7.3); explicit types (`var` is rare); one public type per
    file, named after the type;
  - sub-folders map to sub-namespaces (`Services` → `Forge.Security.Jwt.Client.Services`, `Api` →
    `Forge.Security.Jwt.Client.Api`);
  - private fields `_camelCase`; `IDisposable` through the `Dispose(bool)` pattern; constructor arguments checked for
    null; `ArgumentNullException.ThrowIfNull` does not exist on `netstandard2.0`, so the shared code uses `?? throw new
    ArgumentNullException(nameof(x))` or an `if`;
  - XML documentation on every public member; `GenerateDocumentationFile`, so each target writes its own file under
    `obj/<configuration>/<target>/`. No `DocumentationFile`: one file for every target is written by the parallel target
    builds at once (fixed on 2026-11-15).
- **Build:** the whole solution, in Visual Studio, with Visual Studio's `MSBuild.exe`, or with `dotnet build` (since the
  switch to `Forge.snk`, 2026-11-15):
  - a project builds alone as well (the post-build copy to `..\.Output\` is commented out since 2026-11-15).
- **Before handing over a change:**
  - a build of the solution, all targets, with no warning in this project (none since 2026-11-15);
  - when a target was added or a dependency changed: the package's `.nuspec` dependency groups checked against
    `AI/DESIGN.md` (see `AI/VERIFICATION.md`);
  - a package can be checked without touching `..\.Documents\`: build with `-p:PackageOutputPath=<another folder>\`, or
    build a copy of the solution.
- **Documentation:** every public change is reflected in `README.md` in the same step.
- **Release:**
  1. Raise `AssemblyVersion` in `Forge.Security.Jwt.Client.csproj` (`Version` and `FileVersion` follow it).
  2. This package takes the current version of `Forge.Security.Jwt.Shared` as its minimum dependency: when it needs a
     newer Shared, Shared is raised and released first.
  3. Commit the change before the Release build: the package records the git commit of the build as its source (Zoltán,
     2026-11-15).
  4. Build the solution in Release in Visual Studio (`GeneratePackageOnBuild` is on for Release); the package goes to
     `..\.Documents\`. A Release build of the solution rewrites the package of every project's current version there,
     published or not (see `AI/OPEN.md`).
  5. Zoltán publishes it.
