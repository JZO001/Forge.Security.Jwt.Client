using Forge.Security.Jwt.Client.Api;
using Forge.Security.Jwt.Client.Services;
using Forge.Security.Jwt.Shared.Client.Api;
using Forge.Security.Jwt.Shared.Client.Models;
using Forge.Security.Jwt.Shared.Client.Services;
using Forge.Security.Jwt.Shared.Serialization;
using Forge.Security.Jwt.Shared.Storage;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using System;
using System.Net.Http;

namespace Forge.Security.Jwt.Client
{

    /// <summary>ServiceCollection extension methods</summary>
    public static class ServiceCollectionExtensions
    {

        /// <summary>
        /// Registers the Forge Jwt Client side security services as scoped.
        /// </summary>
        /// <returns>IServiceCollection</returns>
        public static IServiceCollection AddForgeJwtClientAuthenticationCore(this IServiceCollection services,
            Action<JwtClientAuthenticationCoreOptions>
#if NETSTANDARD2_0
#else
            ?
#endif
            configure = null,
            HttpMessageHandler
#if NETSTANDARD2_0
#else
            ?
#endif
            httpMessageHandler = null)
        {
            if (httpMessageHandler == null)
            {
                services.AddHttpClient(Consts.HTTP_CLIENT_FACTORY_NAME);
            }
            else
            {
                services.AddHttpClient(Consts.HTTP_CLIENT_FACTORY_NAME).ConfigurePrimaryHttpMessageHandler(_ => httpMessageHandler);
            }

            return services
                .AddSingleton<DataStore>()
                .AddSingleton<ISerializationProvider, SystemTextJsonSerializer>()
                .AddSingleton<ITokenizedApiCommunicationService, TokenizedApiCommunicationService>()
                .AddSingleton<IAdditionalData, AdditionalData>(serviceProvider =>
                {
                    IOptions<JwtClientAuthenticationCoreOptions> options = serviceProvider.GetService<IOptions<JwtClientAuthenticationCoreOptions>>()
#if NETSTANDARD2_0
#else
                    !
#endif
                    ;
                    AdditionalData logoutData = new AdditionalData();
                    logoutData.SecondaryKeys.AddRange(options.Value.SecondaryKeys);
                    return logoutData;
                })
                .AddScoped<IStorage<ParsedTokenData>, MemoryStorage<ParsedTokenData>>()
                .AddScoped<JwtTokenAuthenticationStateProvider>()
                .AddScoped<IJwtTokenAuthenticationStateProvider>(sp => sp.GetRequiredService<JwtTokenAuthenticationStateProvider>())
                .AddScoped<AuthenticationStateProvider>(sp => sp.GetRequiredService<JwtTokenAuthenticationStateProvider>())
                .AddScoped<IAuthenticationService, AuthenticationService>()
                .AddScoped<IRefreshTokenService, JwtTokenRefreshHostedService>()
                .Configure<JwtClientAuthenticationCoreOptions>(configureOptions =>
                {
                    configure?.Invoke(configureOptions);
                });
        }

        /// <summary>
        /// Registers the Forge Jwt Client side security services as singletons.
        /// </summary>
        /// <returns>IServiceCollection</returns>
        public static IServiceCollection AddForgeJwtClientAuthenticationCoreAsSingleton(this IServiceCollection services,
            Action<JwtClientAuthenticationCoreOptions>
#if NETSTANDARD2_0
#else
            ?
#endif
            configure = null)
        {
            services.AddHttpClient(Consts.HTTP_CLIENT_FACTORY_NAME);

            return services
                .AddSingleton<DataStore>()
                .AddSingleton<ISerializationProvider, SystemTextJsonSerializer>()
                .AddSingleton<ITokenizedApiCommunicationService, TokenizedApiCommunicationService>()
                .AddSingleton<IStorage<ParsedTokenData>, MemoryStorage<ParsedTokenData>>()
                .AddSingleton<JwtTokenAuthenticationStateProvider>()
                .AddSingleton<IJwtTokenAuthenticationStateProvider>(sp => sp.GetRequiredService<JwtTokenAuthenticationStateProvider>())
                .AddSingleton<AuthenticationStateProvider>(sp => sp.GetRequiredService<JwtTokenAuthenticationStateProvider>())
                .AddSingleton<IAdditionalData, AdditionalData>(serviceProvider =>
                {
                    IOptions<JwtClientAuthenticationCoreOptions> options = serviceProvider.GetService<IOptions<JwtClientAuthenticationCoreOptions>>()
#if NETSTANDARD2_0
#else
                    !
#endif
                    ;
                    AdditionalData logoutData = new AdditionalData();
                    logoutData.SecondaryKeys.AddRange(options.Value.SecondaryKeys);
                    return logoutData;
                })
                .AddSingleton<IAuthenticationService, AuthenticationService>()
                .AddSingleton<IRefreshTokenService, JwtTokenRefreshHostedService>()
                .Configure<JwtClientAuthenticationCoreOptions>(configureOptions =>
                {
                    configure?.Invoke(configureOptions);
                });
        }

    }

}
