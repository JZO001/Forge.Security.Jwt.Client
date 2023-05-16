using Forge.Security.Jwt.Shared.Client.Api;
using Forge.Security.Jwt.Shared.Client.Models;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using System;
using System.Net.Http;

namespace Forge.Security.Jwt.Client.Api
{

    /// <summary>Represents a HttpClient with a unique configuration</summary>
    public class ApiCommunicationHttpClientFactory : IApiCommunicationHttpClientFactory
    {

        private readonly ILogger<ApiCommunicationHttpClientFactory> _logger;
        private readonly JwtClientAuthenticationCoreOptions _options;
        private readonly IServiceProvider _serviceProvider;

        /// <summary>Initializes a new instance of the <see cref="ApiCommunicationHttpClientFactory" /> class.</summary>
        /// <param name="options">The options.</param>
        /// <param name="serviceProvider">The serviceProvider.</param>
        /// <param name="logger">The logger.</param>
        /// <exception cref="System.ArgumentNullException">logger
        /// or
        /// options</exception>
        public ApiCommunicationHttpClientFactory(JwtClientAuthenticationCoreOptions options,
            IServiceProvider serviceProvider = null,
            ILogger<ApiCommunicationHttpClientFactory> logger = null)
        {
            if (options == null) throw new ArgumentNullException(nameof(options));

            _logger = logger;
            _options = options;
            _serviceProvider = serviceProvider;
        }

        /// <summary>Initializes a new instance of the <see cref="ApiCommunicationHttpClientFactory" /> class.</summary>
        /// <param name="options">The options.</param>
        /// <param name="serviceProvider">The serviceProvider.</param>
        /// <param name="logger">The options.</param>
        /// <exception cref="System.ArgumentNullException">options</exception>
        public ApiCommunicationHttpClientFactory(IOptions<JwtClientAuthenticationCoreOptions> options,
            IServiceProvider serviceProvider = null,
            ILogger<ApiCommunicationHttpClientFactory> logger = null) : this(options?.Value, serviceProvider, logger)
        {
        }

        /// <summary>Gets the HTTP client.</summary>
        /// <value>The HTTP client.</value>
        public HttpClient GetHttpClient()
        {
            HttpClient
#if NETSTANDARD2_0
#else
                ?
#endif
                httpClient = null;

            if (_options.HttpMessageHandlerFactory == null)
            {
                _logger?.LogDebug($"HttpMessageHandler not set, BaseAddress: {_options.BaseAddress}");

                if (_serviceProvider == null)
                {
                    _logger?.LogDebug($"IServiceProvider not set, BaseAddress: {_options.BaseAddress}");
                    httpClient = new HttpClient { BaseAddress = new Uri(_options.BaseAddress) };
                }
                else
                {
                    _logger?.LogDebug($"IServiceProvider presents, BaseAddress: {_options.BaseAddress}");
                    IHttpClientFactory httpClientFactory = _serviceProvider.GetService<IHttpClientFactory>();
                    httpClient = httpClientFactory.CreateClient(Consts.HTTP_CLIENT_FACTORY_NAME);
                    httpClient.BaseAddress = new Uri(_options.BaseAddress);
                }
            }
            else
            {
                _logger?.LogDebug($"HttpMessageHandler presents, BaseAddress: {_options.BaseAddress}");
                httpClient = new HttpClient(_options.HttpMessageHandlerFactory()) { BaseAddress = new Uri(_options.BaseAddress) };
            }
            return httpClient
#if NETSTANDARD2_0
#else
                !
#endif
                ;
        }

    }

}
