using Forge.Security.Jwt.Shared.Client.Api;
using Forge.Security.Jwt.Shared.Client.Models;
using Forge.Security.Jwt.Shared.Client.Services;
using Forge.Security.Jwt.Shared.Service.Models;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using System;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

namespace Forge.Security.Jwt.Client.Services
{

    /// <summary>User service with basic features</summary>
    public class AuthenticationService : IAuthenticationService, IDisposable
    {

        private readonly ILogger<AuthenticationService> _logger;
        private readonly ITokenizedApiCommunicationService _apiService;
        private readonly IJwtTokenAuthenticationStateProvider _authenticationStateProvider;
        private readonly JwtClientAuthenticationCoreOptions _options;

        /// <summary>Occurs when a user authentication state changed</summary>
        public event EventHandler<UserDataEventArgs>
#if NETSTANDARD2_0
#else
            ?
#endif
            OnUserAuthenticationStateChanged;

        /// <summary>Initializes a new instance of the <see cref="AuthenticationService" /> class.</summary>
        /// <param name="logger">The logger.</param>
        /// <param name="apiService">The API service.</param>
        /// <param name="authenticationStateProvider">The authentication state provider.</param>
        /// <param name="additionalData">Optionally the logout data</param>
        /// <param name="options">Optionally the logout data</param>
        /// <exception cref="System.ArgumentNullException">apiService
        /// or
        /// authenticationStateProvider</exception>
        public AuthenticationService(ILogger<AuthenticationService> logger, 
            ITokenizedApiCommunicationService apiService,
            AuthenticationStateProvider authenticationStateProvider, 
            IAdditionalData additionalData,
            IOptions<JwtClientAuthenticationCoreOptions> options)
        {
            if (logger == null) throw new ArgumentNullException(nameof(logger));
            if (apiService == null) throw new ArgumentNullException(nameof(apiService));
            if (authenticationStateProvider == null) throw new ArgumentNullException(nameof(authenticationStateProvider));
            if (options == null) throw new ArgumentNullException(nameof(options));

            _logger = logger;
            _apiService = apiService;
            _authenticationStateProvider = (IJwtTokenAuthenticationStateProvider)authenticationStateProvider;
            _authenticationStateProvider.AuthenticationStateChanged += AuthenticationStateChangedEventHandler;
            AdditionalData = additionalData;
            _options = options.Value;

            _logger.LogDebug($"AuthenticationService.ctor, ITokenizedApiCommunicationService, hash: {apiService.GetHashCode()}");
            _logger.LogDebug($"AuthenticationService.ctor, AuthenticationStateProvider, hash: {authenticationStateProvider.GetHashCode()}");
            _logger.LogDebug($"AuthenticationService.ctor, IAdditionalData, hash: {additionalData?.GetHashCode()}");
        }

        /// <summary>Finalizes an instance of the <see cref="AuthenticationService" /> class.</summary>
        ~AuthenticationService()
        {
            Dispose(false);
        }

        /// <summary>Gets or sets the additional data, if something need to send at requests</summary>
        /// <value>The logout data.</value>
        public IAdditionalData
#if NETSTANDARD2_0
#else
            ?
#endif
            AdditionalData { get; private set; }

        /// <summary>Authenticates the user with the given credentials</summary>
        /// <typeparam name="TAuthCredentials">The type of the authentication credentials.</typeparam>
        /// <typeparam name="TAuthResult">The type of the authentication result.</typeparam>
        /// <param name="userCredentials">The user credentials.</param>
        /// <returns>Authentication result data</returns>
        public async Task<TAuthResult> AuthenticateUserAsync<TAuthCredentials, TAuthResult>(TAuthCredentials userCredentials)
            where TAuthCredentials : class, IAdditionalData
            where TAuthResult : class, IAuthenticationResponse, new()
        {
            TAuthResult result = new TAuthResult();

            _logger.LogDebug("AuthenticateUserAsync, authenticate user...");

            try
            {
                userCredentials.SecondaryKeys = AdditionalData?.SecondaryKeys?.ToList();
                result = await _apiService.PostAsync<TAuthCredentials, TAuthResult>(_options.AuthenticationUri, userCredentials);
                await _authenticationStateProvider.AuthenticateUserAsync<TAuthResult>(result);
                _logger.LogDebug("AuthenticateUserAsync, authentication was successfull");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, ex.Message);
                _logger.LogDebug("AuthenticateUserAsync, authentication failed");
                await LogoutUserAsync();
                result = new TAuthResult();
            }

            return result;
        }

        /// <summary>Gets the current user information.</summary>
        /// <returns>A data object which responded back by the provider/server/service</returns>
        public async Task<ParsedTokenData
#if NETSTANDARD2_0
#else
            ?
#endif
            > GetCurrentUserInfoAsync()
        {
            ParsedTokenData result = await _authenticationStateProvider.GetParsedTokenDataAsync();

            if (result == null)
            {
                await LogoutUserAsync();
            }

            return result;
        }

        /// <summary>Logs out the current user.</summary>
        /// <returns>True, if the logout was successful, otherwise, False</returns>
        public async Task<bool> LogoutUserAsync()
        {
            _logger.LogDebug("LogoutUserAsync, logging out...");
            ParsedTokenData parsedTokenData = await _authenticationStateProvider.GetParsedTokenDataAsync();
            BooleanResponse
#if NETSTANDARD2_0
#else
            ?
#endif
                response = null;
            if (!string.IsNullOrWhiteSpace(parsedTokenData.AccessToken))
            {
                try
                {
#if NETSTANDARD2_0
                    response = await _apiService.PostAsync<IAdditionalData, BooleanResponse>(_options.LogoutUri, AdditionalData);
#else
#pragma warning disable CS8604 // Possible null reference argument.
#pragma warning disable CS8600 // Converting null literal or possible null value to non-nullable type.
            response = await _apiService.PostAsync<IAdditionalData, BooleanResponse?>(_options.LogoutUri, AdditionalData);
#pragma warning restore CS8600 // Converting null literal or possible null value to non-nullable type.
#pragma warning restore CS8604 // Possible null reference argument.
#endif
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, ex.Message);
                }
            }
            try
            {
                await _authenticationStateProvider.LogoutUserAsync();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, ex.Message);
            }
            bool result = response == null ? false : response.Result;
            _logger.LogDebug($"LogoutUserAsync, logout completed. Result: {result}");
#pragma warning disable CS8602 // Dereference of a possibly null reference.
            return result;
#pragma warning restore CS8602 // Dereference of a possibly null reference.
        }

        /// <summary>Validates the current token.</summary>
        /// <returns>True, if the token is valid, otherwise, False.</returns>
        public async Task<bool> ValidateTokenAsync()
        {
            _logger.LogDebug("ValidateTokenAsync, validating token...");

            bool result = false;

            ParsedTokenData parsedTokenData = await _authenticationStateProvider.GetParsedTokenDataAsync();
            if (parsedTokenData.RefreshTokenExpireAt < DateTime.UtcNow)
            {
                _logger.LogDebug("ValidateTokenAsync, token expired");
                return false;
            }

            TokenRequest request = new TokenRequest();
            request.RefreshTokenString = parsedTokenData.RefreshToken;
            request.SecondaryKeys = AdditionalData?.SecondaryKeys?.ToList();
            BooleanResponse response = await _apiService.PostAsync<TokenRequest, BooleanResponse>(_options.ValidateTokenUri, request);
            if (response != null) result = response.Result;

            _logger.LogDebug($"ValidateTokenAsync, validation result: {result}");

            return result;
        }

        /// <summary>Refreshes the current token and get a new one.</summary>
        /// <returns>The new token, or null, if it is not valid.</returns>
        public async Task<ParsedTokenData
#if NETSTANDARD2_0
#else
            ?
#endif
            > RefreshTokenAsync()
        {
            _logger.LogDebug("RefreshTokenAsync, refreshing token...");
#if NETSTANDARD2_0
            ParsedTokenData
#else
            ParsedTokenData?
#endif
                parsedTokenData = await _authenticationStateProvider.GetParsedTokenDataAsync();
            
            if (parsedTokenData.RefreshTokenExpireAt < DateTime.UtcNow)
            {
                _logger.LogDebug("RefreshTokenAsync, token expired");
                return null;
            }

            TokenRequest request = new TokenRequest();
            request.RefreshTokenString = parsedTokenData.RefreshToken;
            request.SecondaryKeys = AdditionalData?.SecondaryKeys?.ToList();
            parsedTokenData = null;

            try
            {
                JwtTokenResult jwtTokenResult = await _apiService.PostAsync<TokenRequest, JwtTokenResult>(_options.RefreshUri, request);
                await _authenticationStateProvider.AuthenticateUserAsync<JwtTokenResult>(jwtTokenResult);
                parsedTokenData = await _authenticationStateProvider.GetParsedTokenDataAsync();
            }
            catch (Exception ex)
            {
                _logger.LogDebug("RefreshTokenAsync, token refresh failed");
                _logger.LogError(ex, ex.Message);
                if (ex.InnerException != null && ex.InnerException is Shared.Client.Api.HttpRequestException)
                {
                    Shared.Client.Api.HttpRequestException hre = (Shared.Client.Api.HttpRequestException)ex.InnerException;
                    if (hre.StatusCode == System.Net.HttpStatusCode.Unauthorized)
                    {
                        await LogoutUserAsync();
                    }
                    else
                    {
                        throw;
                    }
                }
                else
                {
                    throw;
                }
            }

            _logger.LogDebug("RefreshTokenAsync, token successfully refreshed");

            return parsedTokenData;
        }

        private void AuthenticationStateChangedEventHandler(Task<AuthenticationState> task)
        {
            _logger.LogDebug("AuthenticationStateChangedEventHandler, authentication state changed");
#pragma warning disable CS8602 // Dereference of a possibly null reference.
            if (task.Result.User.Identity.IsAuthenticated)
            {
                ClaimsIdentity claimsIdentity = (ClaimsIdentity)task.Result.User.Identity;
                string userId = claimsIdentity.FindFirst(ClaimTypes.NameIdentifier).Value;
                _logger.LogDebug($"AuthenticationStateChangedEventHandler, authenticated userId: {userId}");
                OnUserAuthenticationStateChanged?.Invoke(this, new UserDataEventArgs(userId));
            }
            else
            {
                _logger.LogDebug("AuthenticationStateChangedEventHandler, no authenticated user");
                OnUserAuthenticationStateChanged?.Invoke(this, new UserDataEventArgs(string.Empty));
            }
#pragma warning restore CS8602 // Dereference of a possibly null reference.
        }

        /// <summary>Performs application-defined tasks associated with freeing, releasing, or resetting unmanaged resources.</summary>
        public void Dispose()
        {
            Dispose(true);
        }

        /// <summary>Releases unmanaged and - optionally - managed resources.</summary>
        /// <param name="disposing">
        ///   <c>true</c> to release both managed and unmanaged resources; <c>false</c> to release only unmanaged resources.</param>
        protected virtual void Dispose(bool disposing)
        {
            if (disposing)
            {
                _authenticationStateProvider.AuthenticationStateChanged -= AuthenticationStateChangedEventHandler;
            }
        }

    }

}
