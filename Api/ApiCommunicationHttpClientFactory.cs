using Forge.Security.Jwt.Shared.Client.Api;
using Forge.Security.Jwt.Shared.Client.Models;
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

        /// <summary>Initializes a new instance of the <see cref="ApiCommunicationHttpClientFactory" /> class.</summary>
        /// <param name="logger">The options.</param>
        /// <param name="options">The options.</param>
        /// <exception cref="System.ArgumentNullException">options</exception>
        public ApiCommunicationHttpClientFactory(ILogger<ApiCommunicationHttpClientFactory> logger, 
            IOptions<JwtClientAuthenticationCoreOptions> options)
        {
            if (logger == null) throw new ArgumentNullException(nameof(logger));
            if (options == null) throw new ArgumentNullException(nameof(options));
            _logger = logger;
            _options = options.Value;
        }

        /// <summary>Initializes a new instance of the <see cref="ApiCommunicationHttpClientFactory" /> class.</summary>
        /// <param name="logger">The logger.</param>
        /// <param name="options">The options.</param>
        /// <exception cref="System.ArgumentNullException">logger
        /// or
        /// options</exception>
        public ApiCommunicationHttpClientFactory(ILogger<ApiCommunicationHttpClientFactory> logger,
            JwtClientAuthenticationCoreOptions options)
        {
            if (logger == null) throw new ArgumentNullException(nameof(logger));
            if (options == null) throw new ArgumentNullException(nameof(options));
            _logger = logger;
            _options = options;
        }

        /// <summary>Gets the HTTP client.</summary>
        /// <value>The HTTP client.</value>
        public HttpClient GetHttpClient()
        {
            HttpClient httpClient = null;
            if (_options.HttpMessageHandlerFactory == null)
            {
                _logger.LogDebug($"HttpMessageHandler not set, BaseAddress: {_options.BaseAddress}");
                httpClient = new HttpClient { BaseAddress = new Uri(_options.BaseAddress) };
            }
            else
            {
                _logger.LogDebug($"HttpMessageHandler presents, BaseAddress: {_options.BaseAddress}");
                httpClient = new HttpClient(_options.HttpMessageHandlerFactory()) { BaseAddress = new Uri(_options.BaseAddress) };
            }
            return httpClient;
        }

    }

}
