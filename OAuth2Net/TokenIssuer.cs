using Microsoft.AspNetCore.Http;
using OAuth2Net.Client;
using OAuth2Net.Token;
using System.Linq;
using System.Net;
using System.Security.Claims;
using System.Threading.Tasks;

namespace OAuth2Net
{
    public interface ITokenIssuer
    {
        RequestDelegate TokenHandler { get; }
    }

    public class TokenIssuer : ITokenIssuer
    {
        private readonly IClientValidator _clientValidator;
        private readonly ITokenGenerator _tokenGenerator;

        public RequestDelegate TokenHandler { get; }
        public TokenIssuerOptions TokenIssuerOptions { get; }

        public TokenIssuer(
              IClientValidator clientValidator
            , ITokenGenerator tokenGenerator
            , TokenIssuerOptions options
        )
        {
            TokenIssuerOptions = options;
            _clientValidator = clientValidator;
            _tokenGenerator = tokenGenerator;
            TokenHandler = HandleTokenRequestAsync;
        }

        protected virtual async Task HandleTokenRequestAsync(HttpContext context)
        {
            var authorzation = context.Request.Headers[OAuth2Consts.Header_Authorization].FirstOrDefault();
            var grantType = context.Request.Form[OAuth2Consts.Form_GrantType].FirstOrDefault();
            var scopes = context.Request.Form[OAuth2Consts.Form_Scope].FirstOrDefault();

            var clientVerifyResult = await _clientValidator.VerifyClientAsync(authorzation, grantType, scopes).ConfigureAwait(false);
            if (!clientVerifyResult.IsSuccess)
            {
                context.Response.StatusCode = (int)HttpStatusCode.BadRequest;
                await context.Response.WriteAsync(clientVerifyResult.Message).ConfigureAwait(false);
                return;
            }

            var scopesArray = scopes.Split(' ');

            switch (grantType)
            {
                case OAuth2Consts.GrantType_Client:
                    // issue token directly
                    var token = await _tokenGenerator.GenerateAsync(
                          GrantType.ClientCredentials
                        , client: clientVerifyResult.Result
                        , scopes: scopesArray
                    ).ConfigureAwait(false);

                    await WriteTokenAsync(context.Response, string.Format(OAuth2Consts.Tmpl_Token1, token, TokenIssuerOptions.ExpiresInSeconds, scopes)).ConfigureAwait(false);
                    break;
                case OAuth2Consts.GrantType_Code:
                    break;
                case OAuth2Consts.GrantType_Owner:
                    // verify username & password
                    break;
                case OAuth2Consts.GrantType_Implicit:
                    break;
                default:
                    context.Response.StatusCode = (int)HttpStatusCode.BadRequest;
                    await context.Response.WriteAsync("invalid grant type").ConfigureAwait(false);
                    break;
            }
        }

        private async Task WriteTokenAsync(HttpResponse response, string token)
        {
            response.ContentType = "application/json;charset=UTF-8";
            response.Headers.Add("Cache-Control", "no-store");
            response.Headers.Add("Pragma", "no-cache");
            await response.WriteAsync(token).ConfigureAwait(false);
        }
    }
}
