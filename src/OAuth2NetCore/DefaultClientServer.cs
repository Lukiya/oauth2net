using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using OAuth2NetCore.Store;
using System;
using System.Linq;
using System.Net;
using System.Threading.Tasks;

namespace OAuth2NetCore
{
    public class DefaultClientServer : IClientServer
    {
        private readonly IStateStore _stateStore;
        private readonly ClientOptions _options;
        public RequestDelegate SignOutRequestHandler { get; }
        public RequestDelegate SignOutCallbackRequestHandler { get; }

        public DefaultClientServer(
            IStateStore stateStore
            , ClientOptions options
        )
        {
            _stateStore = stateStore;
            _options = options;

            SignOutRequestHandler = HandleSignOutRequestAsync;
            SignOutCallbackRequestHandler = HandleSignOutCallbackRequestAsync;
        }

        protected virtual async Task HandleSignOutRequestAsync(HttpContext context)
        {
            // save return url to store
            var returnUrl = context.Request.Query[OAuth2Consts.Form_ReturnUrl].FirstOrDefault() ?? Uri.EscapeDataString("/");
            var state = Guid.NewGuid().ToString("n");
            await _stateStore.AddAsync(state, returnUrl);

            // redirect to auth server
            var clientID = _options.ClientID;
            GetUri(context.Request);
            var callbackUri = new UriBuilder();
            callbackUri.Scheme = context.Request.Scheme;
            callbackUri.Host = context.Request.Host.Value;
            callbackUri.Path = _options.SignOutCallbackPath;
            var targetUri = $"{_options.EndSessionEndpoint}?client_id={clientID}&redirect_uri={Uri.EscapeDataString(callbackUri.ToString())}&state={state}";
            context.Response.Redirect(targetUri);
        }

        private static Uri GetUri(HttpRequest request)
        {
            var builder = new UriBuilder();
            builder.Scheme = request.Scheme;
            builder.Host = request.Host.Value;
            builder.Path = request.Path;
            builder.Query = request.QueryString.ToUriComponent();
            return builder.Uri;
        }

        protected virtual async Task HandleSignOutCallbackRequestAsync(HttpContext context)
        {
            var state = context.Request.Query[OAuth2Consts.Form_State].FirstOrDefault();

            // read return url from store
            var returnUrl = await _stateStore.RemoveAsync(state).ConfigureAwait(false);
            if (!string.IsNullOrWhiteSpace(returnUrl))
            {
                // sign out & redirect to return url
                await context.SignOutAsync().ConfigureAwait(false);
                context.Response.Redirect(returnUrl);
            }
            else
            {
                context.Response.StatusCode = (int)HttpStatusCode.NotFound;
            }
        }
    }
}
