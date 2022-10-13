using Forge.Security.Jwt.Shared.Client.Api;
using Forge.Security.Jwt.Shared.Client.Models;
using Forge.Security.Jwt.Shared.Client.Services;
using Microsoft.Extensions.Hosting;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Forge.Security.Jwt.Client.Services
{

    /// <summary>Automatically refresh the token before it expires</summary>
    public class JwtTokenRefreshService : IHostedService, IDisposable
    {

        private Timer
#if NETSTANDARD2_0
#else
            ?
#endif
            _timer;
        private readonly IAuthenticationService _authenticationService;
        private readonly IJwtTokenAuthenticationStateProvider _jwtTokenAuthenticationStateProvider;
        private ParsedTokenData
#if NETSTANDARD2_0
#else
            ?
#endif
            _parsedTokenData;

        /// <summary>Initializes a new instance of the <see cref="JwtTokenRefreshService" /> class.</summary>
        /// <param name="authenticationService">The authentication service.</param>
        /// <param name="jwtTokenAuthenticationStateProvider">The JWT token authentication state provider.</param>
        /// <exception cref="System.ArgumentNullException">authenticationService
        /// or
        /// jwtTokenAuthenticationStateProvider</exception>
        public JwtTokenRefreshService(IAuthenticationService authenticationService, IJwtTokenAuthenticationStateProvider jwtTokenAuthenticationStateProvider)
        {
            if (authenticationService == null) throw new ArgumentNullException(nameof(authenticationService));
            if (jwtTokenAuthenticationStateProvider == null) throw new ArgumentNullException(nameof(jwtTokenAuthenticationStateProvider));
            _authenticationService = authenticationService;
            _jwtTokenAuthenticationStateProvider = jwtTokenAuthenticationStateProvider;
        }

        /// <summary>Starts the service</summary>
        /// <param name="cancellationToken">CancellationToken</param>
        /// <returns>
        ///   Task
        /// </returns>
        public async Task StartAsync(CancellationToken cancellationToken)
        {
            _timer = new Timer(DoWork, null, Timeout.Infinite, 0);
            _jwtTokenAuthenticationStateProvider.AuthenticationStateChanged += AuthenticationStateChangedEventHandler;
            await ConfigureTimerAsync();
        }

        /// <summary>Stops the service</summary>
        /// <param name="cancellationToken">CancellationToken</param>
        /// <returns>
        ///   Task
        /// </returns>
        public Task StopAsync(CancellationToken cancellationToken)
        {
            _jwtTokenAuthenticationStateProvider.AuthenticationStateChanged -= AuthenticationStateChangedEventHandler;
            _timer?.Change(Timeout.Infinite, 0);
            _timer?.Dispose();
            _timer = null;
            return Task.CompletedTask;
        }

        /// <summary>Performs application-defined tasks associated with freeing, releasing, or resetting unmanaged resources.</summary>
        public void Dispose()
        {
            _timer?.Dispose();
            _timer = null;
        }

        private async void AuthenticationStateChangedEventHandler(Task<Microsoft.AspNetCore.Components.Authorization.AuthenticationState> task)
        {
            await ConfigureTimerAsync();
        }

        private async Task ConfigureTimerAsync()
        {
            _parsedTokenData = await _jwtTokenAuthenticationStateProvider.GetParsedTokenDataAsync();
            if (_parsedTokenData.RefreshTokenExpireAt < DateTime.UtcNow)
            {
                // token has already expired
                _timer?.Change(Timeout.Infinite, 0);
            }
            else
            {
                // start timer
                int dueTime = Convert.ToInt32(TimeSpan.FromTicks(_parsedTokenData.RefreshTokenExpireAt.Ticks - DateTime.UtcNow.Ticks).TotalMilliseconds);
                _timer?.Change(dueTime, 0);
            }
        }

        private void DoWork(object
#if NETSTANDARD2_0
#else
            ?
#endif
            state)
        {
            Task.Run(() => DoWorkAsync());
        }

        private async Task DoWorkAsync()
        {
            try
            {
                await _authenticationService.RefreshTokenAsync();
                await ConfigureTimerAsync();
            }
            catch (Exception)
            {
                _timer?.Change(Timeout.Infinite, 0);
            }
        }

    }

}
