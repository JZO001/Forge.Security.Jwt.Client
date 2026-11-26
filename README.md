# Forge.Security.Jwt.Client

**JWT authentication made simple — across the .NET ecosystem.**

[![NuGet](https://img.shields.io/nuget/v/Forge.Security.Jwt.Client?logo=nuget)](https://www.nuget.org/packages/Forge.Security.Jwt.Client)
[![NuGet Downloads](https://img.shields.io/nuget/dt/Forge.Security.Jwt.Client?logo=nuget)](https://www.nuget.org/packages/Forge.Security.Jwt.Client)
[![License](https://img.shields.io/github/license/JZO001/Forge.Security.Jwt.Client)](https://github.com/JZO001/Forge.Security.Jwt.Client)
[![GitHub Stars](https://img.shields.io/github/stars/JZO001/Forge.Security.Jwt.Client?style=flat&logo=github)](https://github.com/JZO001/Forge.Security.Jwt.Client/stargazers)

![.NET](https://img.shields.io/badge/.NET-8%20%7C%209%20%7C%2010%20%7C%2011-512BD4?logo=dotnet&logoColor=white)
![.NET Standard](https://img.shields.io/badge/.NET%20Standard-2.0-512BD4)
![C%23](https://img.shields.io/badge/Language-C%23-239120)
![Blazor](https://img.shields.io/badge/Blazor-Server%20%26%20WASM-512BD4?logo=blazor)
![Authentication](https://img.shields.io/badge/Authentication-JWT-blue)
![SSO](https://img.shields.io/badge/SSO-Supported-blue)

Forge.Security.Jwt.Client is a client-side JWT (JSON Web Token) authentication and authorization library for .NET applications. It is part of the **Forge JWT Authentication Ecosystem** and provides a reusable authentication client for web, mobile, and desktop applications, including Single Sign-On (SSO) scenarios.

## Features

- Client-side JWT authentication and authorization.
- Bearer token-based authentication scenarios.
- Integration with .NET dependency injection.
- Support for Blazor Server and Blazor WebAssembly (WASM).
- Integration examples for ASP.NET Core Hosted, .NET MAUI, WPF, and Windows Forms applications.
- Standard and optional singleton service registration.
- Integration with the related Forge JWT server and browser storage libraries.

## Target Frameworks

- .NET Standard 2.0
- .NET 8, .NET 9, .NET 10, and .NET 11

## Installation

Install the package from [NuGet](https://www.nuget.org/packages/Forge.Security.Jwt.Client) using one of the following methods.

Add a package reference to your `.csproj` file, replacing `x.x.x` with the desired package version:

```xml
<PackageReference Include="Forge.Security.Jwt.Client" Version="x.x.x" />
```

Or use the .NET CLI:

```bash
dotnet add package Forge.Security.Jwt.Client
```

You can also install the package using the built-in NuGet Package Manager in Visual Studio.

## Setup

### Blazor Server

Register the authentication client services with the service collection in `Startup.cs` (or use `builder.Services` in `Program.cs` with the modern hosting model).

```csharp
public void ConfigureServices(IServiceCollection services)
{
    services.AddForgeJwtClientAuthenticationCore();
}
```

### Blazor WebAssembly

Register the services in `Program.cs` for Blazor WebAssembly.

```csharp
public static async Task Main(string[] args)
{
    var builder = WebAssemblyHostBuilder.CreateDefault(args);
    builder.RootComponents.Add<App>("app");

    builder.Services.AddForgeJwtClientAuthenticationCore();

    await builder.Build().RunAsync();
}
```

### Registering services as singletons

If your application explicitly requires singleton authentication client services, use the following method:

```csharp
builder.Services.AddForgeJwtClientAuthenticationCoreAsSingleton();
```

> **Important:** Singleton registration is not recommended in most scenarios. In particular, avoid sharing user-specific authentication state across users or circuits in Blazor Server. Prefer the standard registration unless the service lifetime is appropriate for your application.

## Usage

The [Forge.Yoda](https://github.com/JZO001/Forge.Yoda) solution contains examples of how to integrate Forge.Security.Jwt.Client into different application types. Look for the projects with `Apps` in their namespaces:

- ASP.NET Core Hosted (Blazor WebAssembly)
- .NET MAUI
- Windows Forms (WinForms)
- WPF (Windows Presentation Foundation)

## Related Projects

The following libraries and examples form the **Forge JWT Authentication Ecosystem** and its supporting components.

| Project | Description |
| --- | --- |
| [Forge.Security.Jwt.Shared](https://github.com/JZO001/Forge.Security.Jwt.Shared) | Shared JWT authentication components. |
| [Forge.Security.Jwt.Service](https://github.com/JZO001/Forge.Security.Jwt.Service) | Server-side JWT authentication services. |
| [Forge.Security.Jwt.Service.Storage.SqlServer](https://github.com/JZO001/Forge.Security.Jwt.Service.Storage.SqlServer) | SQL Server storage integration for the JWT service. |
| [Forge.Security.Jwt.Client.Storage.Browser](https://github.com/JZO001/Forge.Security.Jwt.Client.Storage.Browser) | Browser-based storage integration for the JWT client. |
| [Forge.Wasm.BrowserStorages](https://github.com/JZO001/Forge.Wasm.BrowserStorages) | Browser storage abstractions for .NET and Blazor WebAssembly. |
| [Forge.Wasm.BrowserStorages.NewtonSoft.Json](https://github.com/JZO001/Forge.Wasm.BrowserStorages.NewtonSoft.Json) | Newtonsoft.Json integration for browser storage. |
| [Forge.Yoda](https://github.com/JZO001/Forge.Yoda) | Example applications and integration scenarios. |

## Keywords

.NET, C#, ASP.NET Core, Blazor, Blazor Server, Blazor WebAssembly, WASM,
JWT, JWT authentication, JWT authorization, JSON Web Token, Bearer Token,
JWT client, Single Sign-On (SSO), authentication client, token-based authentication,
client-side authentication, .NET MAUI, WPF, Windows Forms, WinForms,
dependency injection, .NET Standard 2.0, .NET 8, .NET 9, .NET 10, .NET 11.

## Support the Project

**Forge.Security.Jwt.Client** is developed and maintained independently and provided free of charge.

If this library saves you development time, helps your business, or makes your daily work easier, please consider giving the [repository a ⭐ on GitHub](https://github.com/JZO001/Forge.Security.Jwt.Client).

- ⭐ Star the repository on GitHub
- 💬 Share your feedback and experiences
- 🐛 [Report bugs and suggest improvements](https://github.com/JZO001/Forge.Security.Jwt.Client/issues)
- 📢 Recommend the library to other developers
- ☕ Consider sponsoring its continued development

Even a simple GitHub star is a meaningful way to say thank you.

**Open source is free to use, but it is not free to create and maintain.**
