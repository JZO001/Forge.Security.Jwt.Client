# Design

## The parts

| File / folder | Namespace | Role |
| --- | --- | --- |
| `Services/AuthenticationService.cs` | `Forge.Security.Jwt.Client.Services` | `IAuthenticationService`: login, logout, token refresh against the server |
| `Services/JwtTokenAuthenticationStateProvider.cs` | `Forge.Security.Jwt.Client.Services` | The Blazor `AuthenticationStateProvider` built on the parsed token |
| `Services/JwtTokenRefreshHostedService.cs` | `Forge.Security.Jwt.Client.Services` | Refreshes the token in the background |
| `Api/TokenizedApiCommunicationService.cs`, `…Options.cs` | `Forge.Security.Jwt.Client.Api` | HTTP calls with the token (`IHttpClientFactory`) |
| `ServiceCollectionExtensions.cs` | `Forge.Security.Jwt.Client` | `AddForgeJwtClientAuthenticationCore`, `AddForgeJwtClientAuthenticationCoreAsSingleton` |
| `Consts.cs` | `Forge.Security.Jwt.Client` | Constants |

## The targets

| Target | Package references |
| --- | --- |
| `netstandard2.0` | `Microsoft.JSInterop` 3.1.32, `Microsoft.Extensions.Http` 3.1.32 |
| `net8.0` | `Microsoft.JSInterop` 8.0.0, `Microsoft.Extensions.Http` 8.0.0 |
| `net9.0` | `Microsoft.JSInterop` 9.0.0, `Microsoft.Extensions.Http` 9.0.0 |
| `net10.0` | `Microsoft.JSInterop` 10.0.0, `Microsoft.Extensions.Http` 10.0.0 |
| `net11.0` | `Microsoft.JSInterop` 11.0.0, `Microsoft.Extensions.Http` 11.0.0 (added on 2026-11-15) |

`Forge.Security.Jwt.Shared` (project reference) on every target.

## The build and the package

- SDK: `Microsoft.NET.Sdk`. `SignAssembly` with `..\.Documents\Forge.snk`.
- `GenerateDocumentationFile`: each target writes its own `Forge.Security.Jwt.Client.xml` under
  `obj/<configuration>/<target>/`, and the build copies it next to the assembly (since 2026-11-15; before, one
  `DocumentationFile` in the project folder served every target).
- `GeneratePackageOnBuild` for Release; `PackageOutputPath` is `..\.Documents\`.
- The package holds `lib/<target>/Forge.Security.Jwt.Client.dll` and `.xml` for every target, and at its root `LICENSE`
  (the license is stated as `PackageLicenseExpression` `MIT` since 2026-11-15; the file is still packed), `README.md`
  (`PackageReadmeFile`) and `logo.png` (`PackageIcon`, from 2026-11-15).
- `NoWarn` BL0016: the analyzer of the 11.0 ASP.NET Core packages asks for a `try`/`catch` around each JS interop call;
  the library lets these exceptions reach its caller, as on the earlier targets (2026-11-15).
- The post-build copy (`xcopy` of the `.dll`, `.pdb`, `.xml` to `$(SolutionDir).Output\<target>\`) is commented out in
  the project file (Zoltán, 2026-11-15).
- The `Scc*` properties (`SAK`) and the `.vspscc` file belong to the TFS binding of the solution.

## Why each choice was made

- **One package version of the framework libraries per target:** the same pattern as in `Forge.Next.Shared`, where the
  reason is recorded: the package does not force a newer framework package on a consumer than its framework's own.
- **Strong naming:** the seven packages of the solution are signed with the same key, so the assemblies have a stable
  identity. Until 2026-11-15 the projects named the password-protected `Forge.pfx`, which only Visual Studio's MSBuild
  can sign with; since then its key pair as `Forge.snk`, which `dotnet build` can use too.
- **Nullable on the .NET targets only:** `netstandard2.0` compiles with C# 7.3, where `?` on a reference type is an
  error; the `#if NETSTANDARD2_0` blocks keep one source for both.
