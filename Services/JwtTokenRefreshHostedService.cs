using Forge.Security.Jwt.Shared.Client.Models;
using Forge.Security.Jwt.Shared.Client.Services;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using System;
using System.Threading;
using System.Threading.Tasks;

namespace Forge.Security.Jwt.Client.Services
{

    /// <summary>Automatically refresh the token before it expires</summary>
    public class JwtTokenRefreshHostedService : IRefreshTokenService
    {

        private Timer
#if NETSTANDARD2_0
#else
            ?
#endif
            _timer;
        private readonly ILogger<JwtTokenRefreshHostedService> _logger;
        private readonly IAuthenticationService _authenticationService;
        private readonly IJwtTokenAuthenticationStateProvider _authenticationStateProvider;
        private readonly DataStore _dataStore;
        private readonly JwtClientAuthenticationCoreOptions _options;
        private ParsedTokenData
#if NETSTANDARD2_0
#else
            ?
#endif
            _parsedTokenData;

#if NETSTANDARD2_0
        /// <summary>Occurs when authentication required</summary>
        public event EventHandler OnAuthenticationError;
#else
        /// <summary>Occurs when authentication required</summary>
        public event EventHandler? OnAuthenticationError;
#endif

        /// <summary>Initializes a new instance of the <see cref="JwtTokenRefreshHostedService" /> class.</summary>
        /// <param name="logger">The logger.</param>
        /// <param name="authenticationService">The authentication service.</param>
        /// <param name="authenticationStateProvider">The JWT token authentication state provider.</param>
        /// <param name="dataStore">The dataStore.</param>
        /// <param name="options">The options.</param>
        /// <exception cref="System.ArgumentNullException">authenticationService
        /// or
        /// jwtTokenAuthenticationStateProvider</exception>
        public JwtTokenRefreshHostedService(ILogger<JwtTokenRefreshHostedService> logger, 
            IAuthenticationService authenticationService,
            AuthenticationStateProvider authenticationStateProvider,
            DataStore dataStore,
            IOptions<JwtClientAuthenticationCoreOptions> options)
        {
            if (logger == null) throw new ArgumentNullException(nameof(logger));
            if (authenticationService == null) throw new ArgumentNullException(nameof(authenticationService));
            if (authenticationStateProvider == null) throw new ArgumentNullException(nameof(authenticationStateProvider));
            if (dataStore == null) throw new ArgumentNullException(nameof(dataStore));
            if (options == null) throw new ArgumentNullException(nameof(options));

            _logger = logger;
            _authenticationService = authenticationService;
            _authenticationStateProvider = (IJwtTokenAuthenticationStateProvider)authenticationStateProvider;
            _dataStore = dataStore;
            _options = options.Value;
            
            _logger.LogDebug("JwtTokenRefreshHostedService.ctor, IAuthenticationService, hash: {Hash}", authenticationService.GetHashCode());
            _logger.LogDebug("JwtTokenRefreshHostedService.ctor, AuthenticationStateProvider, hash: {Hash}", authenticationStateProvider.GetHashCode());
        }

        /// <summary>Starts the service</summary>
        /// <param name="cancellationToken">CancellationToken</param>
        /// <returns>
        ///   Task
        /// </returns>
        public async Task StartAsync(CancellationToken cancellationToken)
        {
            _logger.LogInformation("StartAsync, starting");

            _timer = new Timer(DoWork, null, Timeout.Infinite, 0);
            
            _authenticationStateProvider.AuthenticationStateChanged += AuthenticationStateChangedEventHandler;

            await ConfigureTimerAsync();

            _logger.LogInformation("StartAsync, started");
        }

        /// <summary>Stops the service</summary>
        /// <param name="cancellationToken">CancellationToken</param>
        /// <returns>
        ///   Task
        /// </returns>
        public Task StopAsync(CancellationToken cancellationToken)
        {
            _logger.LogInformation("StopAsync, stopping");

            _authenticationStateProvider.AuthenticationStateChanged -= AuthenticationStateChangedEventHandler;

            _timer?.Change(Timeout.Infinite, 0);
            _timer?.Dispose();
            _timer = null;

            _logger.LogInformation("StopAsync, stopped");

            return Task.CompletedTask;
        }

        /// <summary>Raises the authentication error event.</summary>
        protected virtual void RaiseOnAuthenticationError()
        {
            OnAuthenticationError?.Invoke(this, EventArgs.Empty);
        }

        private async void AuthenticationStateChangedEventHandler(Task<Microsoft.AspNetCore.Components.Authorization.AuthenticationState> task)
        {
            _logger.LogInformation("AuthenticationStateChangedEventHandler, authentication state changed");

            await ConfigureTimerAsync();
        }

        private async Task ConfigureTimerAsync()
        {
            _parsedTokenData = await GetParsedTokenDataAsync();

            _logger.LogDebug("ConfigureTimerAsync, current time: {CurrentTime}, refresh token will expire: {RefreshTokenExpireAt}", DateTime.UtcNow.ToString("yyyy.MM.dd HH:mm:ss:ttt"), _parsedTokenData.RefreshTokenExpireAt.ToString("yyyy.MM.dd HH:mm:ss:ttt"));
            if (_parsedTokenData.RefreshTokenExpireAt < DateTime.UtcNow)
            {
                // token has already expired
                _logger.LogInformation("ConfigureTimerAsync, refresh token expired. It is not possible to regenerate the current access token, if it exists.");
                _timer?.Change(Timeout.Infinite, 0);
                RaiseOnAuthenticationError();
            }
            else
            {
                // start timer
                int dueTime = Convert.ToInt32(TimeSpan.FromTicks(_parsedTokenData.RefreshTokenExpireAt.Ticks - DateTime.UtcNow.Ticks).TotalMilliseconds) - _options.RefreshTokenBeforeExpirationInMilliseconds;
                if (dueTime < 0) dueTime = 0;
                _logger.LogInformation("ConfigureTimerAsync, timer due time value: {DueTime} ms", dueTime);
                _timer?.Change(dueTime, Timeout.Infinite);
            }
        }

        private async Task<ParsedTokenData> GetParsedTokenDataAsync()
        {
            ParsedTokenData result = _dataStore.TokenData;
            if (string.IsNullOrWhiteSpace(result.AccessToken)) result = await _authenticationStateProvider.GetParsedTokenDataAsync();
            return result;
        }

        private void DoWork(object
#if NETSTANDARD2_0
#else
            ?
#endif
            state)
        {
            // because of WASM, I switch off the timer and give the method to run to the task manager
            _timer?.Change(Timeout.Infinite, 0);
            Task.Run(() => DoWorkAsync());
        }

        private async Task DoWorkAsync()
        {
            try
            {
                _logger.LogInformation("DoWorkAsync, trying to refresh the token...");
                await _authenticationService.RefreshTokenAsync();
                _logger.LogInformation("DoWorkAsync, token successfully refreshed");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "DoWorkAsync, failed to refresh token");

                _timer?.Change(Timeout.Infinite, 0);

                RaiseOnAuthenticationError();

                await Task.Delay(1000);

                await ConfigureTimerAsync();
            }
        }

    }

}
