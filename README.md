# Forge.Security.Jwt.Client
Forge.Security.Jwt.Client is a library that provides client side authentication service for WASM / MAUI client applications.


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
Please find Forge.Yode solution in my repositories, the "Apps" namespace entries in the projects means an application type:
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
