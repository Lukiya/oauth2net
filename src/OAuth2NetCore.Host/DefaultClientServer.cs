using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OAuth;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using OAuth2NetCore.Security;
using OAuth2NetCore.Store;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Threading.Tasks;

namespace OAuth2NetCore.Host
{
    public class DefaultClientServer : IClientServer
    {
        private readonly IStateStore _stateStore;
        private readonly IStateGenerator _stateGenerator;
        private readonly ITokenStore _tokenDTOStore;
        private readonly IHttpClientFactory _httpClientFactory;
        private readonly ILogger<DefaultClientServer> _logger;
        private readonly ClientOptions _options;
        public RequestDelegate SignInRequestHandler { get; }
        public RequestDelegate SignOutRequestHandler { get; }
        public RequestDelegate SignOutCallbackRequestHandler { get; }

        public DefaultClientServer(
            IStateStore stateStore
            , ITokenStore tokenDTOStore
            , IStateGenerator stateGenerator
            , IHttpClientFactory httpClientFactory
            , ILogger<DefaultClientServer> logger
            , ClientOptions options
        )
        {
            _stateStore = stateStore;
            _stateGenerator = stateGenerator;
            _tokenDTOStore = tokenDTOStore;
            _httpClientFactory = httpClientFactory;
            _logger = logger;
            _options = options;

            SignInRequestHandler = HandleSignInRequestAsync;
            SignOutRequestHandler = HandleSignOutRequestAsync;
            SignOutCallbackRequestHandler = HandleSignOutCallbackRequestAsync;
        }

        /// <summary>
        /// handle sign out request
        /// </summary>
        protected virtual async Task HandleSignOutRequestAsync(HttpContext context)
        {
            // save return url to state store
            var returnUrl = context.Request.Query[OAuth2Consts.Form_ReturnUrl].FirstOrDefault() ?? Uri.EscapeDataString("/");
            var state = await _stateGenerator.GenerateAsync();
            await _stateStore.SaveAsync(state, returnUrl);

            // redirect to auth server
            var clientID = _options.ClientID;
            var callbackUri = new UriBuilder();
            callbackUri.Scheme = context.Request.Scheme;
            callbackUri.Host = context.Request.Host.Value;
            callbackUri.Path = _options.SignOutCallbackPath;
            var targetUri = $"{_options.EndSessionEndpoint}?client_id={clientID}&redirect_uri={Uri.EscapeDataString(callbackUri.ToString())}&state={state}";
            context.Response.Redirect(targetUri);
        }

        /// <summary>
        ///  handle sign out callback request
        /// </summary>
        protected virtual async Task HandleSignOutCallbackRequestAsync(HttpContext context)
        {
            var state = context.Request.Query[OAuth2Consts.Form_State].FirstOrDefault();

            // read return url from store
            var returnUrl = await _stateStore.GetThenRemoveAsync(state);
            if (!string.IsNullOrWhiteSpace(returnUrl))
            {
                var endSessionID = context.Request.Query[OAuth2Consts.Form_EndSessionID].FirstOrDefault();
                if (string.IsNullOrWhiteSpace(endSessionID))
                {
                    context.Response.StatusCode = (int)HttpStatusCode.BadRequest;
                    await context.Response.WriteAsync("missing es_id");
                    return;
                }

                var tokenDTO = await _tokenDTOStore.GetTokenDTOAsync();
                if (tokenDTO != null)
                {
                    var httpClient = _httpClientFactory.CreateClient();
                    var resp = await httpClient.PostAsync(_options.EndSessionEndpoint, new FormUrlEncodedContent(new KeyValuePair<string, string>[] {
                        new KeyValuePair<string, string>(OAuth2Consts.Form_State, state),
                        new KeyValuePair<string, string>(OAuth2Consts.Form_EndSessionID, endSessionID),
                        new KeyValuePair<string, string>(OAuth2Consts.Form_ClientID, _options.ClientID),
                        new KeyValuePair<string, string>(OAuth2Consts.Form_ClientSecret, _options.ClientSecret),
                        new KeyValuePair<string, string>(OAuth2Consts.Form_RefreshToken, tokenDTO.RefreshToken),
                    }));
                    if (!resp.IsSuccessStatusCode)
                    {
                        var body = await resp.Content.ReadAsStringAsync();
                        _logger.LogWarning("Post end session request failed [{0}]:\n{1}", resp.StatusCode, body);
                    }
                }

                // sign out & redirect to return url
                await context.OAuth2SignOutAsync();
                context.Response.Redirect(returnUrl);
                return;
            }

            context.Response.StatusCode = (int)HttpStatusCode.NotFound;
        }

        protected virtual async Task HandleSignInRequestAsync(HttpContext context) {
            var returnUrl = context.Request.Query["returnUrl"];
            var t = context.Request.Query["t"];
            var authProps = new AuthenticationProperties();
            if (!string.IsNullOrWhiteSpace(t)) {
                authProps.SetParameter("t", t); // Set login token: {1BC05F9A-1971-418B-ABA7-6C623C008D85}
            }
            authProps.RedirectUri = returnUrl;
            await context.ChallengeAsync(OAuthDefaults.DisplayName, authProps);
        }
    }
}
