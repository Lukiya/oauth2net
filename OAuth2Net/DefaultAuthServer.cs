using Microsoft.AspNetCore.Http;
using OAuth2Net.Client;
using OAuth2Net.Security;
using OAuth2Net.Token;
using System;
using System.Linq;
using System.Net;
using System.Net.Mime;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using System.Web;

namespace OAuth2Net
{
    public class DefaultAuthServer : IAuthServer
    {
        private readonly IClientValidator _clientValidator;
        private readonly ITokenGenerator _tokenGenerator;
        private readonly IResourceOwnerValidator _resourceOwnerValidator;

        public RequestDelegate TokenRequestHandler { get; }
        public RequestDelegate AuthorizeRequestHandler { get; }
        public AuthServerOptions AuthServerOptions { get; }

        public DefaultAuthServer(
              IClientValidator clientValidator
            , ITokenGenerator tokenGenerator
            , IResourceOwnerValidator resourceOwnerValidator
            , AuthServerOptions options
        )
        {
            AuthServerOptions = options;
            _clientValidator = clientValidator;
            _tokenGenerator = tokenGenerator;
            _resourceOwnerValidator = resourceOwnerValidator;
            TokenRequestHandler = HandleTokenRequestAsync;
            AuthorizeRequestHandler = HandleAuthorizeRequestAsync;
        }

        /// <summary>
        /// handle authorize request
        /// </summary>
        protected virtual async Task HandleAuthorizeRequestAsync(HttpContext context)
        {
            var respType = context.Request.Query[OAuth2Consts.Form_ResponseType].FirstOrDefault();
            var clientID = context.Request.Query[OAuth2Consts.Form_ClientID].FirstOrDefault();
            var redirectURI = context.Request.Query[OAuth2Consts.Form_RedirectUri].FirstOrDefault();
            var scopesStr = context.Request.Query[OAuth2Consts.Form_Scope].FirstOrDefault();
            var state = context.Request.Query[OAuth2Consts.Form_State].FirstOrDefault();

            // verify client
            var clientVerifyResult = await _clientValidator.VerifyClientAsync(
                  clientID: clientID
                , responseType: respType
                , redirectURI: redirectURI
                , scopesStr: scopesStr
                , state: state
            ).ConfigureAwait(false);
            if (!clientVerifyResult.IsSuccess)
            {
                await WriteErrorAsync(context.Response, HttpStatusCode.BadRequest, clientVerifyResult.MsgCode, clientVerifyResult.MsgCodeDescription).ConfigureAwait(false);
                return;
            }

            switch (respType)
            {
                case OAuth2Consts.ResponseType_Code:
                    // authorization code
                    break;
                case OAuth2Consts.ResponseType_Token:
                    // implicit
                    await HandleImplicitTokenRequestAsync(context, clientVerifyResult.Result, scopesStr, redirectURI, state).ConfigureAwait(false);
                    break;
                default:
                    await WriteErrorAsync(context.Response, HttpStatusCode.BadRequest, OAuth2Consts.Err_unsupported_response_type).ConfigureAwait(false);
                    break;
            }
        }

        /// <summary>
        /// handle token reqeust
        /// </summary>
        protected virtual async Task HandleTokenRequestAsync(HttpContext context)
        {
            // get parametes from request
            var authorzation = context.Request.Headers[OAuth2Consts.Header_Authorization].FirstOrDefault();
            var grantTypeStr = context.Request.Form[OAuth2Consts.Form_GrantType].FirstOrDefault();
            var scopesStr = context.Request.Form[OAuth2Consts.Form_Scope].FirstOrDefault();

            // verify client
            var clientVerifyResult = await _clientValidator.VerifyClientAsync(authorzation, grantTypeStr, scopesStr).ConfigureAwait(false);
            if (!clientVerifyResult.IsSuccess)
            {
                var httpStatusCode = clientVerifyResult.MsgCode == OAuth2Consts.Err_invalid_client ? HttpStatusCode.Unauthorized : HttpStatusCode.BadRequest;
                await WriteErrorAsync(context.Response, httpStatusCode, clientVerifyResult.MsgCode, clientVerifyResult.MsgCodeDescription).ConfigureAwait(false);
                return;
            }

            switch (grantTypeStr)
            {
                case OAuth2Consts.GrantType_Client:
                    await HandleClientCredentialsTokenRequestAsync(context, clientVerifyResult.Result, scopesStr).ConfigureAwait(false);
                    break;
                case OAuth2Consts.GrantType_Code:

                    break;
                case OAuth2Consts.GrantType_Owner:
                    await HandleResourceOwnerTokenRequestAsync(context, clientVerifyResult.Result, scopesStr).ConfigureAwait(false);
                    break;
                case OAuth2Consts.GrantType_RefreshToken:
                    break;
                default:
                    await WriteErrorAsync(context.Response, HttpStatusCode.BadRequest, OAuth2Consts.Err_unsupported_grant_type).ConfigureAwait(false);
                    break;
            }
        }

        /// <summary>
        /// handle client credentials token request
        /// </summary>
        protected virtual async Task HandleClientCredentialsTokenRequestAsync(HttpContext context, IClient client, string scopesStr)
        {
            // issue token directly
            var token = await _tokenGenerator.GenerateAsync(
                                context: context
                              , grantType: GrantType.ClientCredentials
                              , client: client
                              , scopes: scopesStr.Split(' ')
                              , username: client.ID
                          ).ConfigureAwait(false);

            await WriteTokenAsync(context.Response, token, scopesStr).ConfigureAwait(false);
        }

        /// <summary>
        /// handle authorization code token request
        /// </summary>
        protected virtual async Task HandleAuthorizationCodeTokenRequestAsync(HttpContext context, IClient client, string scopesStr)
        {
            // exchange token by using auhorization code
        }

        /// <summary>
        /// handle resource owner grant type request
        /// </summary>
        protected virtual async Task HandleResourceOwnerTokenRequestAsync(HttpContext context, IClient client, string scopesStr)
        {
            // verify username & password
            var username = context.Request.Form[OAuth2Consts.Form_Username].FirstOrDefault();
            var password = context.Request.Form[OAuth2Consts.Form_Password].FirstOrDefault();
            var ownerVerifyResult = await _resourceOwnerValidator.VertifyAsync(username, password).ConfigureAwait(false);
            if (ownerVerifyResult.Result)
            {
                var token = await _tokenGenerator.GenerateAsync(
                      context: context
                    , grantType: GrantType.ResourceOwner
                    , client: client
                    , scopes: scopesStr.Split(' ')
                    , username: username
                ).ConfigureAwait(false);

                await WriteTokenAsync(context.Response, token, scopesStr).ConfigureAwait(false);
            }
            else
            {
                await WriteErrorAsync(context.Response, HttpStatusCode.BadRequest, ownerVerifyResult.MsgCode, ownerVerifyResult.MsgCodeDescription).ConfigureAwait(false);
            }
        }

        /// <summary>
        /// handle implicit token request
        /// </summary>
        protected virtual async Task HandleImplicitTokenRequestAsync(HttpContext context, IClient client, string scopesStr, string redirectURI, string state)
        {
            if (!context.User.Identity.IsAuthenticated)
            {
                await context.ChallengeAsync().ConfigureAwait(false);
            }
            else
            {
                var token = await _tokenGenerator.GenerateAsync(
                    context: context
                    , grantType: GrantType.Implicit
                    , client: client
                    , scopes: scopesStr.Split(' ')
                    , username: context.User.Identity.Name
                ).ConfigureAwait(false);

                context.Response.Redirect($"{redirectURI}?{OAuth2Consts.Form_AccessToken}={Uri.EscapeDataString(token)}&{OAuth2Consts.Form_TokenType}=Bearer&{OAuth2Consts.Form_ExpiresIn}={AuthServerOptions.ExpiresInSeconds}&{OAuth2Consts.Form_Scope}={Uri.EscapeDataString(scopesStr)}&state={Uri.EscapeDataString(state)}");
            }
        }

        /// <summary>
        /// write token to browser
        /// </summary>
        protected virtual async Task WriteTokenAsync(HttpResponse response, string token, string scopes)
        {
            response.ContentType = OAuth2Consts.ContentType_Json;
            response.Headers.Add(OAuth2Consts.Header_CacheControl, OAuth2Consts.Header_CacheControl_Value);
            response.Headers.Add(OAuth2Consts.Header_Pragma, OAuth2Consts.Header_Pragma_Value);
            await response.WriteAsync(GenereateTokenJson(token, scopes)).ConfigureAwait(false);
        }

        /// <summary>
        /// write error to browser
        /// </summary>
        protected virtual async Task WriteErrorAsync(HttpResponse response, HttpStatusCode statusCode, string error, string errorDescription = null)
        {
            errorDescription = errorDescription ?? error;
            response.StatusCode = (int)statusCode;
            response.ContentType = OAuth2Consts.ContentType_Json;
            response.Headers.Add(OAuth2Consts.Header_CacheControl, OAuth2Consts.Header_CacheControl_Value);
            response.Headers.Add(OAuth2Consts.Header_Pragma, OAuth2Consts.Header_Pragma_Value);
            await response.WriteAsync(string.Format(OAuth2Consts.Format_Error, error, errorDescription)).ConfigureAwait(false);
        }

        protected virtual string GenereateTokenJson(string token, string scopes) => string.Format(OAuth2Consts.Format_Token1, token, AuthServerOptions.ExpiresInSeconds, scopes);
        protected virtual string GenereateTokenJson(string token, string refreshToken, string scopes) => string.Format(OAuth2Consts.Format_Token2, token, refreshToken, AuthServerOptions.ExpiresInSeconds, scopes);
    }
}
