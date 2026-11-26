# Forge.Security.Jwt.Client
Forge.Security.Jwt.Client is a library that provides client side authentication service for client applications.


## Installing

To install the package add the following line to you csproj file replacing x.x.x with the latest version number:

```
<PackageReference Include="Forge.Security.Jwt.Client" Version="x.x.x" />
```

You can also install via the .NET CLI with the following command:

```
dotnet add package Forge.Security.Jwt.Client
```

If you're using Visual Studio you can also install via the built in NuGet package manager.

## Setup

You will need to register the authentication client services with the service collection in your _Startup.cs_ file in Blazor Server.

```c#
public void ConfigureServices(IServiceCollection services)
{
    services.AddForgeJwtClientAuthenticationCore();
}
``` 

Or in your _Program.cs_ file in Blazor WebAssembly.

```c#
public static async Task Main(string[] args)
{
    var builder = WebAssemblyHostBuilder.CreateDefault(args);
    builder.RootComponents.Add<App>("app");

    builder.Services.AddForgeJwtClientAuthenticationCore();

    await builder.Build().RunAsync();
}
```

### Registering services as Singleton
If you would like to register authentication client services as singletons, it is possible by using the following method:

```csharp
builder.Services.AddForgeJwtClientAuthenticationCoreAsSingleton();
```

This method is not recommended in the most cases, try to avoid using it.

## Usage
I have created a few examples about how to use Forge.Security.Jwt.Client in WASM / MAUI application.
Please find Forge.Yoda solution in my repositories, the "Apps" namespace entries in the projects means an application type:
- ASP.NET Core Hosted
- MAUI
- WinForms
- WPF


Please also check the following projects in my repositories:
- Forge.Yoda
- Forge.Security.Jwt.Service
- Forge.Security.Jwt.Service.Storage.SqlServer
- Forge.Security.Jwt.Client
- Forge.Security.Jwt.Client.Storage.Browser
- Forge.Wasm.BrowserStorages
- Forge.Wasm.BrowserStorages.NewtonSoft.Json

## Support the Project

**Forge.Security.Jwt.Client** is developed and maintained independently and provided free of charge.

If this library saves you development time, helps your business, or makes your daily work easier, please consider giving the repository a ⭐ on GitHub.

- ⭐ Star the repository on GitHub
- 💬 Share your feedback and experiences
- 🐛 Report bugs and suggest improvements
- 📢 Recommend the library to other developers
- ☕ Consider sponsoring its continued development

Even a simple GitHub star is a meaningful way to say thank you.

**Open source is free to use, but it is not free to create and maintain.**
