using Forge.Security.Jwt.Shared;
using Forge.Security.Jwt.Shared.Client.Api;
using Forge.Security.Jwt.Shared.Client.Models;
using Forge.Security.Jwt.Shared.Client.Services;
using Forge.Security.Jwt.Shared.Storage;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

namespace Forge.Security.Jwt.Client.Services
{

    /// <summary>Jwt Token based AuthenticationStateProvider implementation</summary>
    public class JwtTokenAuthenticationStateProvider : AuthenticationStateProvider, IJwtTokenAuthenticationStateProvider
    {

        private readonly IStorage<ParsedTokenData> _storageService;
        private readonly ITokenizedApiCommunicationService _apiService;

        /// <summary>The parsed token storage key</summary>
        public const string PARSED_TOKEN_STORAGE_KEY = "__parsedToken";

        private bool _firstPassSignal = true;

        /// <summary>Initializes a new instance of the <see cref="JwtTokenAuthenticationStateProvider" /> class.</summary>
        /// <param name="storage">The storage service.</param>
        /// <param name="apiService">The communication service.</param>
        public JwtTokenAuthenticationStateProvider(IStorage<ParsedTokenData> storage, ITokenizedApiCommunicationService apiService)
        {
            _storageService = storage;
            _apiService = apiService;
        }

        /// <summary>Asynchronously gets an <see cref="T:Microsoft.AspNetCore.Components.Authorization.AuthenticationState">AuthenticationState</see> that describes the current user.</summary>
        /// <returns>
        /// A task that, when resolved, gives an <see cref="T:Microsoft.AspNetCore.Components.Authorization.AuthenticationState">AuthenticationState</see> instance that describes the current user.
        /// </returns>
        public override async Task<AuthenticationState> GetAuthenticationStateAsync()
        {
            ParsedTokenData parsedTokenData = await GetParsedTokenDataAsync();

            if (string.IsNullOrEmpty(parsedTokenData.AccessToken))
            {
                _firstPassSignal = false;
                return new AuthenticationState(new ClaimsPrincipal(new ClaimsIdentity()));
            }

            if (_firstPassSignal)
            {
                _firstPassSignal = false;
                try
                {
                    await AuthenticateUser(parsedTokenData);
                }
                catch (Exception)
                {
                    await LogoutUser();
                    return new AuthenticationState(new ClaimsPrincipal(new ClaimsIdentity()));
                }
            }

            return new AuthenticationState(new ClaimsPrincipal(new ClaimsIdentity(parsedTokenData.Claims, "jwt")));
        }

        /// <summary>Authenticates the user with the gives login response</summary>
        /// <typeparam name="TAuthenticationResponse">The type of the login response.</typeparam>
        /// <param name="authenticationResponse">The login response.</param>
        /// <returns>Task</returns>
        public async Task AuthenticateUser<TAuthenticationResponse>(TAuthenticationResponse authenticationResponse) where TAuthenticationResponse : IAuthenticationResponse, new()
        {
            ParsedTokenData parsedTokenData = await ParseToken<TAuthenticationResponse>(authenticationResponse);
            await AuthenticateUserInner(parsedTokenData);
        }

        /// <summary>Authenticates the user with the given authentication response.</summary>
        /// <param name="parsedTokenData">The parsed token data.</param>
        /// <exception cref="Microsoft.IdentityModel.Tokens.SecurityTokenException">Invalid token</exception>
        public async Task AuthenticateUser(ParsedTokenData parsedTokenData)
        {
            if (parsedTokenData == null) throw new ArgumentNullException(nameof(parsedTokenData));
            await AuthenticateUserInner(parsedTokenData);
        }

        /// <summary>Marks the user as logged out</summary>
        /// <returns>Task</returns>
        public async Task LogoutUser()
        {
            ClaimsPrincipal anonymusUser = new ClaimsPrincipal(new ClaimsIdentity());
            Task<AuthenticationState> authenticationState = Task.FromResult(new AuthenticationState(anonymusUser));
            await _storageService.RemoveAsync(PARSED_TOKEN_STORAGE_KEY);
            _apiService.AccessToken = string.Empty;
            NotifyAuthenticationStateChanged(authenticationState);
        }

        /// <summary>Authenticates the user with the given token</summary>
        /// <param name="parsedTokenData">The parsed token data.</param>
        /// <exception cref="Microsoft.IdentityModel.Tokens.SecurityTokenException">Invalid token</exception>
        protected virtual async Task AuthenticateUserInner(ParsedTokenData parsedTokenData)
        {
            string
#if NETSTANDARD2_0
#else
            ?
#endif
                userId = parsedTokenData.Claims.Where(x => x.Type == ClaimTypes.NameIdentifier).Select(x => x.Value).FirstOrDefault();
            if (string.IsNullOrEmpty(userId))
            {
                throw new SecurityTokenException("Invalid token");
            }
            await _storageService.SetAsync(PARSED_TOKEN_STORAGE_KEY, parsedTokenData);
            _apiService.AccessToken = parsedTokenData.AccessToken;
            ClaimsPrincipal authenticatedUser = new ClaimsPrincipal(new ClaimsIdentity(new[] { new Claim(ClaimTypes.NameIdentifier, userId) }, "apiauth"));
            Task<AuthenticationState> authenticationState = Task.FromResult(new AuthenticationState(authenticatedUser));
            NotifyAuthenticationStateChanged(authenticationState);
        }

        /// <summary>Gets the parsed/extracted data asynchronously from the security token.</summary>
        /// <returns>
        ///   ParsedTokenData
        /// </returns>
        public async Task<ParsedTokenData> GetParsedTokenDataAsync()
        {
            ParsedTokenData result = await _storageService.GetAsync(PARSED_TOKEN_STORAGE_KEY);
            if (result == null || IsTokenExpired(result.AccessTokenExpireAt))
            {
                result = new ParsedTokenData();
            }
            else
            {
                // restore claims
                result.Claims.AddRange(JwtParserHelper.ParseClaimsFromJwt(result.AccessToken));
            }
            return result;
        }

        /// <summary>Parses the given authentication tokens.</summary>
        /// <typeparam name="TAuthenticationResponse">The type of the login response.</typeparam>
        /// <param name="loginResponse">The login response.</param>
        /// <returns>
        ///   ParsedTokenData
        /// </returns>
        protected virtual async Task<ParsedTokenData> ParseToken<TAuthenticationResponse>(TAuthenticationResponse loginResponse) where TAuthenticationResponse : IAuthenticationResponse, new()
        {
            ParsedTokenData result = new ParsedTokenData();

            if (string.IsNullOrWhiteSpace(loginResponse.AccessToken))
            {
                return result;
            }

            List<Claim> claims = JwtParserHelper.ParseClaimsFromJwt(loginResponse.AccessToken);
#pragma warning disable CS8600 // Converting null literal or possible null value to non-nullable type.
            string expireDateStr = claims.Where(x => x.Type == "exp").Select(x => x.Value).FirstOrDefault();
#pragma warning restore CS8600 // Converting null literal or possible null value to non-nullable type.
            //DateTime expiredDate = new DateTime(long.Parse(String.IsNullOrEmpty(expireDateStr) ? "0" : expireDateStr));
            DateTime expiredDate = EpochTime.DateTime(Convert.ToInt64(Math.Truncate(Convert.ToDouble(expireDateStr, CultureInfo.InvariantCulture))));

            if (IsTokenExpired(expiredDate))
            {
                await LogoutUser();
                return result;
            }

            result.Claims.AddRange(claims);
            result.AccessTokenExpireAt = expiredDate;
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

    }

}
