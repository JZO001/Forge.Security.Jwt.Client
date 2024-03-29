﻿using System;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using Forge.Security.Jwt.Shared.Client.Api;
using Microsoft.Extensions.Logging;
using Forge.Security.Jwt.Shared.Serialization;
using Microsoft.Extensions.Options;
using System.Threading;
using Forge.Security.Jwt.Shared.Client.Models;

namespace Forge.Security.Jwt.Client.Api
{

    /// <summary>API communication implementation</summary>
    public class TokenizedApiCommunicationService : ITokenizedApiCommunicationService
    {

        private readonly ILogger<TokenizedApiCommunicationService> _logger;
        private readonly IApiCommunicationHttpClientFactory _apiCommunicationHttpClientFactory;
        private readonly ISerializationProvider _serializer;
        private readonly DataStore _dataStore;
        private readonly TokenizedApiCommunicationServiceOptions _options;

        /// <summary>Occurs before the request sent out to prepare it manually</summary>
        public event EventHandler<HttpRequestMessageEventArgs>
#if NETSTANDARD2_0
#else
            ? 
#endif
            OnPrepareRequest;

        /// <summary>Occurs after the response arrived. Gain full control over the content deserialization.</summary>
        public event EventHandler<HttpResponseMessageEventArgs>
#if NETSTANDARD2_0
#else
            ?
#endif
            OnPrepareResponse;

        /// <summary>Initializes a new instance of the <see cref="TokenizedApiCommunicationService" /> class.</summary>
        /// <param name="logger">The logger.</param>
        /// <param name="apiCommunicationHttpClientFactory">The HTTP client.</param>
        /// <param name="serializer">The serializer.</param>
        /// <param name="dataStore">The dataStore.</param>
        /// <param name="options">The options.</param>
        public TokenizedApiCommunicationService(ILogger<TokenizedApiCommunicationService> logger,
            IApiCommunicationHttpClientFactory apiCommunicationHttpClientFactory,
            ISerializationProvider serializer,
            DataStore dataStore,
            TokenizedApiCommunicationServiceOptions options)
        {
            if (logger == null) throw new ArgumentNullException(nameof(logger));
            if (apiCommunicationHttpClientFactory == null) throw new ArgumentNullException(nameof(apiCommunicationHttpClientFactory));
            if (serializer == null) throw new ArgumentNullException(nameof(serializer));
            if (dataStore == null) throw new ArgumentNullException(nameof(dataStore));
            if (options == null) throw new ArgumentNullException(nameof(options));

            _logger = logger;
            _apiCommunicationHttpClientFactory = apiCommunicationHttpClientFactory;
            _serializer = serializer;
            _dataStore = dataStore;
            _options = options;

            _logger.LogDebug($"TokenizedApiCommunicationService.ctor, IApiCommunicationHttpClientFactory, hash: {apiCommunicationHttpClientFactory.GetHashCode()}");
            _logger.LogDebug($"TokenizedApiCommunicationService.ctor, ISerializationProvider, hash: {serializer.GetHashCode()}");
        }

        /// <summary>Initializes a new instance of the <see cref="TokenizedApiCommunicationService" /> class.</summary>
        /// <param name="logger">The logger.</param>
        /// <param name="apiCommunicationHttpClientFactory">The HTTP client.</param>
        /// <param name="serializer">The serializer.</param>
        /// <param name="dataStore">The dataStore.</param>
        /// <param name="options">The options.</param>
        public TokenizedApiCommunicationService(ILogger<TokenizedApiCommunicationService> logger, 
            IApiCommunicationHttpClientFactory apiCommunicationHttpClientFactory,
            ISerializationProvider serializer,
            DataStore dataStore,
            IOptions<TokenizedApiCommunicationServiceOptions> options)
            : this(logger, apiCommunicationHttpClientFactory, serializer, dataStore, options?.Value)
        {
        }

        /// <summary>Gets or sets the default encoding for sending.</summary>
        /// <value>The default encoding is UTF8.</value>
        public Encoding DefaultEncoding { get; set; } = Encoding.UTF8;

        /// <summary>Gets data</summary>
        /// <typeparam name="TResult">The type of the result.</typeparam>
        /// <param name="uri">The URI.</param>
        /// <param name="cancellationToken">The cancellation token.</param>
        /// <returns>The result object</returns>
        public async Task<TResult> GetAsync<TResult>(string uri, CancellationToken cancellationToken)
#if NETSTANDARD || NETCOREAPP3_1
            where TResult : class
#endif
        {
            return await ApiCall<TResult>(HttpMethod.Get, uri, null, cancellationToken);
        }

        /// <summary>Posts data or creates a resource</summary>
        /// <typeparam name="TData">The type of the data.</typeparam>
        /// <typeparam name="TResult">The type of the result data.</typeparam>
        /// <param name="uri">The URI.</param>
        /// <param name="data">The data.</param>
        /// <param name="cancellationToken">The cancellation token.</param>
        /// <returns>The result data</returns>
        public async Task<TResult> PostAsync<TData, TResult>(string uri, TData
#if NETSTANDARD2_0
#else
            ?
#endif
            data, CancellationToken cancellationToken)
#if NETSTANDARD || NETCOREAPP3_1
            where TData : class
            where TResult : class
#endif
        {
            return await ApiCall<TResult>(HttpMethod.Post, uri, data, cancellationToken);
        }

        /// <summary>Puts data or update a resource</summary>
        /// <typeparam name="TData">The type of the data.</typeparam>
        /// <typeparam name="TResult">The type of the result data.</typeparam>
        /// <param name="uri">The URI.</param>
        /// <param name="data">The data.</param>
        /// <param name="cancellationToken">The cancellation token.</param>
        /// <returns>The result data</returns>
        public async Task<TResult> PutAsync<TData, TResult>(string uri, TData
#if NETSTANDARD2_0
#else
            ?
#endif
            data, CancellationToken cancellationToken)
#if NETSTANDARD || NETCOREAPP3_1
            where TData : class
            where TResult : class
#endif
        {
            return await ApiCall<TResult>(HttpMethod.Put, uri, data, cancellationToken);
        }

        /// <summary>Deletes a</summary>
        /// <typeparam name="TResult">The type of the result.</typeparam>
        /// <param name="uri">The URI.</param>
        /// <param name="cancellationToken">The cancellation token.</param>
        /// <returns>The return data</returns>
        public async Task<TResult> DeleteAsync<TResult>(string uri, CancellationToken cancellationToken)
#if NETSTANDARD || NETCOREAPP3_1
            where TResult : class
#endif
        {
            return await ApiCall<TResult>(HttpMethod.Delete, uri, null, cancellationToken);
        }

        /// <summary>Perform the API call with the given parameters.</summary>
        /// <typeparam name="TResult">The type of the result.</typeparam>
        /// <param name="httpMethod">The HTTP method.</param>
        /// <param name="uri">The URI.</param>
        /// <param name="data">The data.</param>
        /// <param name="cancellationToken">The cancellation token.</param>
        /// <returns>The return value</returns>
        /// <exception cref="Shared.Client.Api.HttpRequestException"></exception>
        protected virtual async Task<TResult> ApiCall<TResult>(HttpMethod httpMethod, string uri, object
#if NETSTANDARD2_0
#else
            ?
#endif
            data, CancellationToken cancellationToken)
#if NETSTANDARD || NETCOREAPP3_1
            where TResult : class
#endif
        {
            TResult
#if NETSTANDARD2_0
#else
            ?
#endif
                result = default;

            HttpClient
#if NETSTANDARD2_0
#else
                ?
#endif
                httpClient = null;
            try
            {
                HttpRequestMessage request = new HttpRequestMessage(httpMethod, uri);

                var prepareRequestEvent = OnPrepareRequest;
                if (prepareRequestEvent == null)
                {
                    _options.Request_Header_Accepts.ForEach(item => request.Headers.Accept.Add(item));

                    if (data != null)
                    {
                        request.Content = new StringContent(_serializer.Serialize(data), _options.RequestEncoding, _options.RequestMediaType);
                    }

                    if (!string.IsNullOrEmpty(_dataStore.TokenData.AccessToken))
                    {
                        request.Headers.Add("Authorization", $"Bearer {_dataStore.TokenData.AccessToken}");
                    }

                    if (!string.IsNullOrEmpty(_dataStore.UserAgent))
                    {
                        request.Headers.Add("user-agent", _dataStore.UserAgent);
                    }
                }
                else
                {
                    prepareRequestEvent(this, new HttpRequestMessageEventArgs(request, data));
                }

                httpClient = _apiCommunicationHttpClientFactory.GetHttpClient();
                _logger.LogDebug($"ApiCall, sending {httpMethod.Method} to baseAddress: {httpClient.BaseAddress}, uri: {uri}");
                HttpResponseMessage response = await httpClient.SendAsync(request, cancellationToken);
                _logger.LogDebug($"ApiCall, response arrived from baseAddress: {httpClient.BaseAddress}, uri: {uri}, method: {httpMethod.Method}");

                string
#if NETSTANDARD2_0
#else
            ?
#endif
                    jsonResult = await response.Content.ReadAsStringAsync();

                if (!response.IsSuccessStatusCode)
                {
                    _logger.LogDebug($"ApiCall, response indicates an unsuccessful operation from {httpClient.BaseAddress}{uri}, method: {httpMethod.Method}, status code: {response.StatusCode}");
                    throw new Shared.Client.Api.HttpRequestException(response.StatusCode, jsonResult);
                }

                var prepareResponseEvent = OnPrepareResponse;
                if (prepareResponseEvent == null)
                {
                    result = _serializer.Deserialize<TResult>(jsonResult);
                }
                else
                {
                    HttpResponseMessageEventArgs ev = new HttpResponseMessageEventArgs(response, typeof(TResult));
                    prepareResponseEvent(this, ev);
#if NETSTANDARD2_0
                    TResult responseData = (TResult)ev.ResponseData;
#else
#pragma warning disable CS8600 // Converting null literal or possible null value to non-nullable type.
                    TResult? responseData = (TResult)ev.ResponseData;
#pragma warning restore CS8600 // Converting null literal or possible null value to non-nullable type.
#endif
                    result = responseData;
                }
            }
            catch (Shared.Client.Api.HttpRequestException)
            {
                throw;
            }
            catch (Exception e)
            {
                _logger.LogError(e, e.Message);
                throw;
            }
            finally
            {
                httpClient?.Dispose();
            }

#pragma warning disable CS8603 // Possible null reference return.
            return result;
#pragma warning restore CS8603 // Possible null reference return.
        }

    }

}
