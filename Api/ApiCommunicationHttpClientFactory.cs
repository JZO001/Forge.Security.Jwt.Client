using Forge.Security.Jwt.Shared.Client.Api;
using System;
using System.Net.Http;

namespace Forge.Security.Jwt.Client.Api
{

    /// <summary>Represents a HttpClient with a unique configuration</summary>
    public class ApiCommunicationHttpClientFactory : IApiCommunicationHttpClientFactory
    {

        private HttpClient _httpClient;

        /// <summary>Initializes a new instance of the <see cref="ApiCommunicationHttpClientFactory" /> class.</summary>
        /// <param name="client">The client.</param>
        public ApiCommunicationHttpClientFactory(HttpClient client)
        {
            if (client == null) throw new ArgumentNullException(nameof(client));
            _httpClient = client;
        }

        /// <summary>Gets the HTTP client.</summary>
        /// <value>The HTTP client.</value>
        public HttpClient GetHttpClient()
        {
            return _httpClient;
        }

    }

}
