using Forge.Security.Jwt.Shared.Client.Api;
using Forge.Security.Jwt.Shared.Client.Models;
using Forge.Security.Jwt.Shared.Client.Services;
using Forge.Security.Jwt.Shared.Service.Models;
using Microsoft.AspNetCore.Components.Authorization;
using System;
using System.Security.Claims;
using System.Threading.Tasks;

namespace Forge.Security.Jwt.Client.Services
{

    /// <summary>User service with basic features</summary>
    public class AuthenticationService : IAuthenticationService, IDisposable
    {

        private static string _authenticationUri = "api/auth/login";
        private static string _logoutUri = "api/auth/logout";
        private static string _validateTokenUri = "api/auth/validate-token";
        private static string _refreshUri = "api/auth/refresh-token";

        private ITokenizedApiCommunicationService _apiService;
        private AuthenticationStateProvider _authenticationStateProvider;

        /// <summary>Occurs when a user authentication state changed</summary>
        public event EventHandler<UserDataEventArgs>
#if NETSTANDARD2_0
#else
            ?
#endif
            OnUserAuthenticationStateChanged;

        /// <summary>Initializes a new instance of the <see cref="AuthenticationService" /> class.</summary>
        /// <param name="apiService">The API service.</param>
        /// <param name="authenticationStateProvider">The authentication state provider.</param>
        /// <param name="additionalData">Optionally the logout data</param>
        /// <exception cref="System.ArgumentNullException">apiService
        /// or
        /// authenticationStateProvider</exception>
        public AuthenticationService(ITokenizedApiCommunicationService apiService, AuthenticationStateProvider authenticationStateProvider, IAdditionalData additionalData)
        {
            if (apiService == null) throw new ArgumentNullException(nameof(apiService));
            if (authenticationStateProvider == null) throw new ArgumentNullException(nameof(authenticationStateProvider));

            _apiService = apiService;
            _authenticationStateProvider = authenticationStateProvider;
            _authenticationStateProvider.AuthenticationStateChanged += AuthenticationStateChangedEventHandler;
            AdditionalData = additionalData;
        }

        /// <summary>Finalizes an instance of the <see cref="AuthenticationService" /> class.</summary>
        ~AuthenticationService()
        {
            Dispose(false);
        }

        /// <summary>Gets or sets the authentication URI.</summary>
        /// <value>The authentication URI.</value>
        public static string AuthenticationUri 
        {
            get => _authenticationUri;
            set
            {
                if (string.IsNullOrEmpty(value)) throw new ArgumentNullException(nameof(value));
                _authenticationUri = value;
            }
        }

        /// <summary>Gets or sets the logout URI.</summary>
        /// <value>The logout URI.</value>
        public static string LogoutUri 
        { 
            get => _logoutUri;
            set
            {
                if (string.IsNullOrEmpty(value)) throw new ArgumentNullException(nameof(value));
                _logoutUri = value;
            }
        }

        /// <summary>Gets or sets the validation URI.</summary>
        /// <value>The logout URI.</value>
        public static string ValidateTokenUri
        {
            get => _validateTokenUri;
            set
            {
                if (string.IsNullOrEmpty(value)) throw new ArgumentNullException(nameof(value));
                _validateTokenUri = value;
            }
        }

        /// <summary>Gets or sets the refresh URI.</summary>
        /// <value>The logout URI.</value>
        public static string RefreshUri
        {
            get => _refreshUri;
            set
            {
                if (string.IsNullOrEmpty(value)) throw new ArgumentNullException(nameof(value));
                _refreshUri = value;
            }
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

            try
            {
                result = await _apiService.PostAsync<TAuthCredentials, TAuthResult>(_authenticationUri, userCredentials);
                await ((IJwtTokenAuthenticationStateProvider)_authenticationStateProvider).AuthenticateUser<TAuthResult>(result);
            }
            catch (HttpRequestException)
            {
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
            ParsedTokenData result = await ((IJwtTokenAuthenticationStateProvider)_authenticationStateProvider).GetParsedTokenDataAsync();

            if (result == null)
            {
                await LogoutUserAsync();
            }

            return result;
        }

        /// <summary>Logs out the current user.</summary>
        /// <returns>Task</returns>
        public async Task LogoutUserAsync()
        {
#if NETSTANDARD2_0
            _ = await _apiService.PostAsync<IAdditionalData, object>(_logoutUri, AdditionalData);
#else
#pragma warning disable CS8604 // Possible null reference argument.
            _ = await _apiService.PostAsync<IAdditionalData, object?>(_logoutUri, AdditionalData);
#pragma warning restore CS8604 // Possible null reference argument.
#endif
            await ((IJwtTokenAuthenticationStateProvider)_authenticationStateProvider).LogoutUser();
        }

        /// <summary>Validates the current token.</summary>
        /// <returns>True, if the token is valid, otherwise, False.</returns>
        public async Task<TokenValidationResponse> ValidateTokenAsync()
        {
            ParsedTokenData parsedTokenData = await ((IJwtTokenAuthenticationStateProvider)_authenticationStateProvider).GetParsedTokenDataAsync();
            if (parsedTokenData.RefreshTokenExpireAt < DateTime.UtcNow)
            {
                return new TokenValidationResponse();
            }

            TokenRequest request = new TokenRequest();
            request.RefreshTokenString = parsedTokenData.RefreshToken;
            request.SecondaryKeys = AdditionalData?.SecondaryKeys;
            return await _apiService.PostAsync<TokenRequest, TokenValidationResponse>(_validateTokenUri, request);
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
#if NETSTANDARD2_0
            ParsedTokenData
#else
            ParsedTokenData?
#endif
                parsedTokenData = await ((IJwtTokenAuthenticationStateProvider)_authenticationStateProvider).GetParsedTokenDataAsync();
            
            if (parsedTokenData.RefreshTokenExpireAt < DateTime.UtcNow)
            {
                return null;
            }

            TokenRequest request = new TokenRequest();
            request.RefreshTokenString = parsedTokenData.RefreshToken;
            request.SecondaryKeys = AdditionalData?.SecondaryKeys;
            parsedTokenData = null;

            try
            {
                JwtTokenResult jwtTokenResult = await _apiService.PostAsync<TokenRequest, JwtTokenResult>(_refreshUri, request);
                await ((IJwtTokenAuthenticationStateProvider)_authenticationStateProvider).AuthenticateUser<JwtTokenResult>(jwtTokenResult);
                parsedTokenData = await ((IJwtTokenAuthenticationStateProvider)_authenticationStateProvider).GetParsedTokenDataAsync();
            }
            catch (Shared.Client.Api.HttpRequestException ex)
            {
                if (ex.StatusCode == System.Net.HttpStatusCode.Unauthorized)
                {
                    await LogoutUserAsync();
                }
                else
                {
                    throw;
                }
            }

            return parsedTokenData;
        }

        private void AuthenticationStateChangedEventHandler(Task<AuthenticationState> task)
        {
#pragma warning disable CS8602 // Dereference of a possibly null reference.
            if (task.Result.User.Identity.IsAuthenticated)
            {
                ClaimsIdentity claimsIdentity = (ClaimsIdentity)task.Result.User.Identity;
                string userId = claimsIdentity.FindFirst(ClaimTypes.NameIdentifier).Value;
                OnUserAuthenticationStateChanged?.Invoke(this, new UserDataEventArgs(userId));
            }
            else
            {
                OnUserAuthenticationStateChanged?.Invoke(this, new UserDataEventArgs(String.Empty));
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
