using Forge.Security.Jwt.Shared;
using Forge.Security.Jwt.Shared.Client.Api;
using Forge.Security.Jwt.Shared.Client.Models;
using Forge.Security.Jwt.Shared.Client.Services;
using Forge.Security.Jwt.Shared.Storage;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using Microsoft.JSInterop;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Security.Claims;
using System.Threading;
using System.Threading.Tasks;

namespace Forge.Security.Jwt.Client.Services
{

    /// <summary>Jwt Token based AuthenticationStateProvider implementation</summary>
    public class JwtTokenAuthenticationStateProvider : AuthenticationStateProvider, IJwtTokenAuthenticationStateProvider
    {

        private static IRefreshTokenService _refreshService;
        private static int _lastHashcode = 0;

        private readonly ILogger<JwtTokenAuthenticationStateProvider> _logger;
        private readonly IStorage<ParsedTokenData> _storageService;
        private readonly ITokenizedApiCommunicationService _apiService;
        private readonly IServiceProvider _serviceProvider;

        /// <summary>The parsed token storage key</summary>
        public const string PARSED_TOKEN_STORAGE_KEY = "__parsedToken";

        private bool _firstPassSignal = true;

        /// <summary>
        /// An event that provides notification when the <see cref="AuthenticationState"/>
        /// has changed. For example, this event may be raised if a user logs in or out.
        /// This is a static event.
        /// </summary>
        public static event AuthenticationStateChangedHandler
#if NETSTANDARD2_0
#else
            ?
#endif
            OnAuthenticationStateStaticChanged;

        /// <summary>Initializes a new instance of the <see cref="JwtTokenAuthenticationStateProvider" /> class.</summary>
        /// <param name="logger">The logger.</param>
        /// <param name="storage">The storage service.</param>
        /// <param name="apiService">The communication service.</param>
        /// <param name="serviceProvider">The service provider</param>
        public JwtTokenAuthenticationStateProvider(ILogger<JwtTokenAuthenticationStateProvider> logger, 
            IStorage<ParsedTokenData> storage, 
            ITokenizedApiCommunicationService apiService,
            IServiceProvider serviceProvider)
        {
            if (logger == null) throw new ArgumentNullException(nameof(logger));
            if (storage == null) throw new ArgumentNullException(nameof(storage));
            if (apiService == null) throw new ArgumentNullException(nameof(apiService));
            if (serviceProvider == null) throw new ArgumentNullException(nameof(serviceProvider));
            _logger = logger;
            _storageService = storage;
            _apiService = apiService;
            _serviceProvider = serviceProvider;

            _logger.LogDebug($"JwtTokenAuthenticationStateProvider.ctor, IStorage<ParsedTokenData>, hash: {storage.GetHashCode()}");
            _logger.LogDebug($"JwtTokenAuthenticationStateProvider.ctor, ITokenizedApiCommunicationService, hash: {apiService.GetHashCode()}");
        }

        /// <summary>Asynchronously gets an <see cref="T:Microsoft.AspNetCore.Components.Authorization.AuthenticationState">AuthenticationState</see> that describes the current user.</summary>
        /// <returns>
        /// A task that, when resolved, gives an <see cref="T:Microsoft.AspNetCore.Components.Authorization.AuthenticationState">AuthenticationState</see> instance that describes the current user.
        /// </returns>
        public override async Task<AuthenticationState> GetAuthenticationStateAsync()
        {
            if (string.IsNullOrWhiteSpace(_apiService.UserAgent))
            {
                IJSRuntime jsRuntime = null;
                try
                {
                    jsRuntime = _serviceProvider.GetService(typeof(IJSRuntime)) as IJSRuntime;
                }
                catch (Exception) { }
                if (jsRuntime == null)
                {
                    _apiService.UserAgent = ".";
                }
                else
                {
                    _apiService.UserAgent = await jsRuntime.InvokeAsync<string>("eval", "(function() { return window.navigator.userAgent; })();");
                }
            }
            if (_refreshService != null && _lastHashcode != GetHashCode())
            {
                IRefreshTokenService service = _refreshService;
                _refreshService = null;
                await service?.StopAsync(CancellationToken.None);
            }
            if (_refreshService == null)
            {
                lock (typeof(JwtTokenAuthenticationStateProvider))
                {
                    if (_refreshService == null)
                    {
                        _lastHashcode = GetHashCode();
                        _refreshService = _serviceProvider.GetService(typeof(IRefreshTokenService)) as IRefreshTokenService;
                    }
                }
                if (_refreshService != null)
                {
                    await _refreshService.StartAsync(CancellationToken.None);
                }
            }

            ParsedTokenData parsedTokenData = await GetParsedTokenDataAsync();

            if (string.IsNullOrEmpty(parsedTokenData.AccessToken))
            {
                _logger.LogDebug("GetAuthenticationStateAsync, no access token present, unauthenticated");
                _firstPassSignal = false;
                return new AuthenticationState(new ClaimsPrincipal(new ClaimsIdentity()));
            }

            if (_firstPassSignal)
            {
                _firstPassSignal = false;
                try
                {
                    _logger.LogDebug("GetAuthenticationStateAsync, authenticating user");
                    await AuthenticateUserAsync(parsedTokenData);
                    _logger.LogDebug("GetAuthenticationStateAsync, user authenticated");
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, ex.Message);
                    _logger.LogDebug("GetAuthenticationStateAsync, failed to re-authenticate user. Logging out...");
                    await LogoutUserAsync();
                    _logger.LogDebug("GetAuthenticationStateAsync, user logged out...");
                    return new AuthenticationState(new ClaimsPrincipal(new ClaimsIdentity()));
                }
            }

            _logger.LogDebug("GetAuthenticationStateAsync, user authenticated by token");

            return new AuthenticationState(new ClaimsPrincipal(new ClaimsIdentity(parsedTokenData.Claims, "jwt")));
        }

        /// <summary>Authenticates the user with the gives login response</summary>
        /// <typeparam name="TAuthenticationResponse">The type of the login response.</typeparam>
        /// <param name="authenticationResponse">The login response.</param>
        /// <returns>Task</returns>
        public async Task AuthenticateUserAsync<TAuthenticationResponse>(TAuthenticationResponse authenticationResponse) where TAuthenticationResponse : IAuthenticationResponse, new()
        {
            ParsedTokenData parsedTokenData = await ParseTokenAsync(authenticationResponse);
            await AuthenticateUserInnerAsync(parsedTokenData);
        }

        /// <summary>Authenticates the user with the given authentication response.</summary>
        /// <param name="parsedTokenData">The parsed token data.</param>
        /// <exception cref="Microsoft.IdentityModel.Tokens.SecurityTokenException">Invalid token</exception>
        public async Task AuthenticateUserAsync(ParsedTokenData parsedTokenData)
        {
            if (parsedTokenData == null) throw new ArgumentNullException(nameof(parsedTokenData));
            await AuthenticateUserInnerAsync(parsedTokenData);
        }

        /// <summary>Marks the user as logged out</summary>
        /// <returns>Task</returns>
        public async Task LogoutUserAsync()
        {
            _logger.LogDebug("LogoutUserAsync, logging out...");
            ClaimsPrincipal anonymusUser = new ClaimsPrincipal(new ClaimsIdentity());
            Task<AuthenticationState> authenticationState = Task.FromResult(new AuthenticationState(anonymusUser));
            try
            {
                await _storageService.RemoveAsync(PARSED_TOKEN_STORAGE_KEY);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, ex.Message);
            }
            _apiService.AccessToken = string.Empty;
            _logger.LogDebug("LogoutUserAsync, logged out");
            NotifyAuthenticationStateChanged(authenticationState);
            NotifyAuthenticationStateStaticChanged(authenticationState);
        }

        /// <summary>Authenticates the user with the given token</summary>
        /// <param name="parsedTokenData">The parsed token data.</param>
        /// <exception cref="Microsoft.IdentityModel.Tokens.SecurityTokenException">Invalid token</exception>
        protected virtual async Task AuthenticateUserInnerAsync(ParsedTokenData parsedTokenData)
        {
            string
#if NETSTANDARD2_0
#else
            ?
#endif
                userId = parsedTokenData.Claims.Where(x => x.Type == ClaimTypes.NameIdentifier).Select(x => x.Value).FirstOrDefault();
            if (string.IsNullOrEmpty(userId))
            {
                _logger.LogError("AuthenticateUserInnerAsync, no userId found in Claims");
                throw new SecurityTokenException("Invalid token");
            }
            try
            {
                await _storageService.SetAsync(PARSED_TOKEN_STORAGE_KEY, parsedTokenData);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, ex.Message);
            }
            _apiService.AccessToken = parsedTokenData.AccessToken;
            ClaimsPrincipal authenticatedUser = new ClaimsPrincipal(new ClaimsIdentity(new[] { new Claim(ClaimTypes.NameIdentifier, userId) }, "apiauth"));
            Task<AuthenticationState> authenticationState = Task.FromResult(new AuthenticationState(authenticatedUser));
            _logger.LogDebug("GetAuthenticationStateAsync, user authenticated by api auth");
            NotifyAuthenticationStateChanged(authenticationState);
            NotifyAuthenticationStateStaticChanged(authenticationState);
        }

        /// <summary>Gets the parsed/extracted data asynchronously from the security token.</summary>
        /// <returns>
        ///   ParsedTokenData
        /// </returns>
        public async Task<ParsedTokenData> GetParsedTokenDataAsync()
        {
            _logger.LogDebug("GetParsedTokenDataAsync, reading stored token");

            ParsedTokenData result = null;
            try
            {
                result = await _storageService.GetAsync(PARSED_TOKEN_STORAGE_KEY);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, ex.Message);
            }

            if (result == null || IsTokenExpired(result.AccessTokenExpireAt))
            {
                if (result == null) 
                    _logger.LogDebug("GetParsedTokenDataAsync, token does not exist");
                else
                    _logger.LogDebug("GetParsedTokenDataAsync, token expired");

                result = new ParsedTokenData();
            }
            else
            {
                // restore claims
                result.Claims.Clear();
                result.Claims.AddRange(JwtParserHelper.ParseClaimsFromJwt(result.AccessToken));
            }
            _logger.LogDebug("GetParsedTokenDataAsync, completed");
            return result;
        }

        /// <summary>Parses the given authentication tokens.</summary>
        /// <param name="loginResponse">The login response.</param>
        /// <returns>
        ///   ParsedTokenData
        /// </returns>
        public virtual async Task<ParsedTokenData> ParseTokenAsync(IAuthenticationResponse loginResponse)
        {
            ParsedTokenData result = new ParsedTokenData();

            if (string.IsNullOrWhiteSpace(loginResponse.AccessToken))
            {
                return result;
            }

            List<Claim> claims = JwtParserHelper.ParseClaimsFromJwt(loginResponse.AccessToken);
#pragma warning disable CS8600 // Converting null literal or possible null value to non-nullable type.
            string accessTokenExpireDateStr = claims.Where(x => x.Type == "exp").Select(x => x.Value).FirstOrDefault();
#pragma warning restore CS8600 // Converting null literal or possible null value to non-nullable type.
            //DateTime expiredDate = new DateTime(long.Parse(String.IsNullOrEmpty(expireDateStr) ? "0" : expireDateStr));
            DateTime accessTokenExpiredDate = EpochTime.DateTime(Convert.ToInt64(Math.Truncate(Convert.ToDouble(accessTokenExpireDateStr, CultureInfo.InvariantCulture))));

            if (IsTokenExpired(accessTokenExpiredDate))
            {
                await LogoutUserAsync();
                return result;
            }

            result.Claims.AddRange(claims);
            result.AccessTokenExpireAt = accessTokenExpiredDate;
            result.AccessToken = loginResponse.AccessToken;
            result.RefreshTokenExpireAt = loginResponse.RefreshTokenExpireAt;
            result.RefreshToken = loginResponse.RefreshToken;

            return result;
        }

        /// <summary>Determines whether the token expired</summary>
        /// <param name="expireDate">The expire date.</param>
        /// <returns>
        ///   <c>true</c> if the token expired, otherwise, <c>false</c>.</returns>
        protected bool IsTokenExpired(DateTime expireDate)
        {
            return expireDate < DateTime.UtcNow;
        }

        /// <summary>
        /// Raises the <see cref="OnAuthenticationStateStaticChanged"/> event.
        /// </summary>
        /// <param name="task">A <see cref="Task"/> that supplies the updated <see cref="AuthenticationState"/>.</param>
        protected static void NotifyAuthenticationStateStaticChanged(Task<AuthenticationState> task)
        {
            if (task == null)
            {
                throw new ArgumentNullException(nameof(task));
            }

            OnAuthenticationStateStaticChanged?.Invoke(task);
        }

    }

}
