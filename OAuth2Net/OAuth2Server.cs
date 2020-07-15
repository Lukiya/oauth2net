using Microsoft.AspNetCore.Http;
using OAuth2Net.Security;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Threading.Tasks;

namespace OAuth2Net
{
    public interface IOAuth2Server
    {
        RequestDelegate TokenHandler { get; }
        //Task<MessageResult<IClient>> VerifyClientAsync(string authorzation);
        //Task<MessageResult<IClient>> VerifyClientAsync(string authorzation, string grantType, string scopes);
    }

    public class OAuth2Server : IOAuth2Server
    {
        //private readonly ILogger<OAuth2Server> _logger;
        //private readonly IClientStore _clientStore;
        private readonly IClientValidator _clientValidator;
        private readonly ICertProvider _certProvider;
        private readonly IClaimGenerator _claimGenerator;
        private readonly ITokenGenerator _tokenGenerator;

        public RequestDelegate TokenHandler { get; }

        public OAuth2Server(/*IClientStore clientStore, ILogger<OAuth2Server> logger,*/
            IClientValidator clientValidator
            , ICertProvider certProvider
            , IClaimGenerator claimGenerator
            , ITokenGenerator tokenGenerator
        )
        {
            //_logger = logger;
            //_clientStore = clientStore;
            _clientValidator = clientValidator;
            _certProvider = certProvider;
            _claimGenerator = claimGenerator;
            _tokenGenerator = tokenGenerator;
            TokenHandler = HandleTokenRequestAsync;
        }

        protected virtual async Task HandleTokenRequestAsync(HttpContext context)
        {
            var authorzation = context.Request.Headers[Consts.Header_Authorization].FirstOrDefault();
            var grantType = context.Request.Form[Consts.Form_GrantType].FirstOrDefault();
            var scopes = context.Request.Form[Consts.Form_Scope].FirstOrDefault();

            var clientVerifyResult = await _clientValidator.VerifyClientAsync(authorzation, grantType, scopes).ConfigureAwait(false);
            if (!clientVerifyResult.IsSuccess)
            {
                context.Response.StatusCode = (int)HttpStatusCode.BadRequest;
                await context.Response.WriteAsync(clientVerifyResult.Message).ConfigureAwait(false);
                return;
            }

            //var payload = new Dictionary<string, object>();
            //payload["client_id"] = clientVerifyResult.Result.ID;
            //payload["scope"] = scopes.Split(' ');

            //var claims = await _claimGenerator.GenerateAsync().ConfigureAwait(false);
            //if (claims.Any())
            //{
            //    foreach (var kv in claims)
            //    {
            //        if (!payload.ContainsKey(kv.Key))
            //        {
            //            payload.Add(kv.Key, kv.Value);
            //        }
            //    }
            //}

            switch (grantType)
            {
                case Consts.GrantType_Client:
                    // issue token directly
                    //payload["name"] = clientVerifyResult.Result.ID;
                    //payload["role"] = "1";
                    var token = await _tokenGenerator.GenerateAsync(3600).ConfigureAwait(false);
                    context.Response.ContentType = "application/json;charset=UTF-8";
                    context.Response.Headers.Add("Cache-Control", "no-store");
                    context.Response.Headers.Add("Pragma", "no-cache");
                    await context.Response.WriteAsync(string.Format(Consts.Tmpl_Token1, token, 3600, scopes)).ConfigureAwait(false);
                    break;
                case Consts.GrantType_Code:
                    break;
                case Consts.GrantType_Owner:
                    // verify username & password
                    break;
                case Consts.GrantType_Implicit:
                    break;
                default:
                    context.Response.StatusCode = (int)HttpStatusCode.BadRequest;
                    await context.Response.WriteAsync("invalid grant type").ConfigureAwait(false);
                    break;
            }
        }
    }
}
