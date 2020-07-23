using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using OAuth2Net.Client;
using OAuth2Net.Model;
using OAuth2Net.Security;
using OAuth2Net.Store;
using OAuth2Net.Token;
using System;
using System.Linq;
using System.Net;
using System.Threading.Tasks;

namespace OAuth2Net
{
    public class DefaultAuthServer : IAuthServer
    {
        private readonly IClientValidator _clientValidator;
        private readonly ITokenGenerator _tokenGenerator;
        private readonly IAuthCodeStore _authCodeStore;
        private readonly ITokenStore _tokenStore;
        private readonly IAuthCodeGenerator _authCodeGenerator;
        private readonly IResourceOwnerValidator _resourceOwnerValidator;
        private readonly ILogger<DefaultAuthServer> _logger;

        public RequestDelegate TokenRequestHandler { get; }
        public RequestDelegate AuthorizeRequestHandler { get; }
        public AuthServerOptions AuthServerOptions { get; }

        public DefaultAuthServer(
              IClientValidator clientValidator
            , ITokenGenerator tokenGenerator
            , IAuthCodeStore authCodeStore
            , ITokenStore tokenStore
            , IAuthCodeGenerator authCodeGenerator
            , IResourceOwnerValidator resourceOwnerValidator
            , ILogger<DefaultAuthServer> logger
            , AuthServerOptions options
        )
        {
            _clientValidator = clientValidator;
            _tokenGenerator = tokenGenerator;
            _resourceOwnerValidator = resourceOwnerValidator;
            _logger = logger;
            _authCodeStore = authCodeStore;
            this._tokenStore = tokenStore;
            this._authCodeGenerator = authCodeGenerator;
            TokenRequestHandler = HandleTokenRequestAsync;
            AuthorizeRequestHandler = HandleAuthorizeRequestAsync;
            AuthServerOptions = options;
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
                    await HandleAuthorizationCodeRequestAsync(context, clientVerifyResult.Result, scopesStr, redirectURI, state).ConfigureAwait(false);
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
        /// handle authorization code request
        /// </summary>
        protected virtual async Task HandleAuthorizationCodeRequestAsync(HttpContext context, IClient client, string scopesStr, string redirectUri, string state)
        {
            if (!context.User.Identity.IsAuthenticated)
            {
                await context.ChallengeAsync().ConfigureAwait(false);
            }
            else
            {
                var code = await _authCodeGenerator.GenerateAsync().ConfigureAwait(false);
                await _authCodeStore.SaveAsync(
                    code,
                    new TokenRequestInfo
                    {
                        ClientID = client.ID,
                        Scopes = scopesStr,
                        RedirectUri = redirectUri,
                        Username = context.User.Identity.Name,
                    }
                ).ConfigureAwait(false);

                context.Response.Redirect($"{redirectUri}?{OAuth2Consts.Form_Code}={code}&{OAuth2Consts.Form_State}={Uri.EscapeDataString(state)}");
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
                var token = await _tokenGenerator.GenerateAccessTokenAsync(
                    context: context
                    , grantType: GrantType.Implicit
                    , client: client
                    , scopes: scopesStr.Split(' ')
                    , username: context.User.Identity.Name
                ).ConfigureAwait(false);

                context.Response.Redirect($"{redirectURI}?{OAuth2Consts.Form_AccessToken}={Uri.EscapeDataString(token)}&{OAuth2Consts.Form_TokenType}=Bearer&{OAuth2Consts.Form_ExpiresIn}={AuthServerOptions.ExpiresInSeconds}&{OAuth2Consts.Form_Scope}={Uri.EscapeDataString(scopesStr)}&{OAuth2Consts.Form_State}={Uri.EscapeDataString(state)}");
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
            MessageResult<IClient> clientVerifyResult;
            if (grantTypeStr == OAuth2Consts.GrantType_AuthorizationCode)
            {
                // auth code grant doesn't post scopes 
                clientVerifyResult = await _clientValidator.VerifyClientAsync(authorzation, grantTypeStr).ConfigureAwait(false);
            }
            else
            {
                // other scopes must post scopes
                clientVerifyResult = await _clientValidator.VerifyClientAsync(authorzation, grantTypeStr, scopesStr).ConfigureAwait(false);
            }

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
                case OAuth2Consts.GrantType_AuthorizationCode:
                    await HandleAuthorizationCodeTokenRequestAsync(context, clientVerifyResult.Result).ConfigureAwait(false);
                    break;
                case OAuth2Consts.GrantType_ResourceOwner:
                    await HandleResourceOwnerTokenRequestAsync(context, clientVerifyResult.Result, scopesStr).ConfigureAwait(false);
                    break;
                case OAuth2Consts.GrantType_RefreshToken:
                    await HandleRefreshTokenRequestAsync(context, clientVerifyResult.Result).ConfigureAwait(false);
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
            var token = await _tokenGenerator.GenerateAccessTokenAsync(
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
        protected virtual async Task HandleAuthorizationCodeTokenRequestAsync(HttpContext context, IClient client)
        {
            // exchange token by using auhorization code
            var code = context.Request.Form[OAuth2Consts.Form_Code].FirstOrDefault();
            var clientID = context.Request.Form[OAuth2Consts.Form_ClientID].FirstOrDefault();
            var redirectUri = context.Request.Form[OAuth2Consts.Form_RedirectUri].FirstOrDefault();

            var tokenRequestInfo = await _authCodeStore.GetAsync(code).ConfigureAwait(false);
            if (null == tokenRequestInfo)
            {
                var errDetail = "invalid authorization code";
                await WriteErrorAsync(context.Response, HttpStatusCode.BadRequest, OAuth2Consts.Err_invalid_request, errDetail);
                return;
            }

            if (client.ID != clientID || clientID != tokenRequestInfo.ClientID)
            {
                var errDetail = $"client id doesn't match, original: '{tokenRequestInfo.ClientID}', current: '{client.ID}'";
                await WriteErrorAsync(context.Response, HttpStatusCode.BadRequest, OAuth2Consts.Err_invalid_request, errDetail);
                return;
            }

            if (redirectUri != tokenRequestInfo.RedirectUri)
            {
                var errDetail = $"redirect uri doesn't match, original: '{tokenRequestInfo.RedirectUri}', current: '{redirectUri}'";
                await WriteErrorAsync(context.Response, HttpStatusCode.BadRequest, OAuth2Consts.Err_invalid_request, errDetail);
                return;
            }

            // issue token
            await IssueTokenByRequestInfoAsync(context, GrantType.AuthorizationCode, client, tokenRequestInfo).ConfigureAwait(false);
        }

        /// <summary>
        /// handle resource owner grant type request
        /// </summary>
        protected virtual async Task HandleResourceOwnerTokenRequestAsync(HttpContext context, IClient client, string scopesStr)
        {
            // verify username & password
            var username = context.Request.Form[OAuth2Consts.Form_Username].FirstOrDefault();
            var password = context.Request.Form[OAuth2Consts.Form_Password].FirstOrDefault();
            var success = await _resourceOwnerValidator.VertifyAsync(username, password).ConfigureAwait(false);
            if (success)
            {// pass, issue token
                await IssueTokenByRequestInfoAsync(context, GrantType.ResourceOwner, client, new TokenRequestInfo
                {
                    ClientID = client.ID,
                    Scopes = scopesStr,
                    Username = username,
                }).ConfigureAwait(false);
            }
            else
            {
                await WriteErrorAsync(context.Response, HttpStatusCode.BadRequest, OAuth2Consts.Err_invalid_grant, "username password doesn't match").ConfigureAwait(false);
            }
        }

        /// <summary>
        /// handle refresh token grant type request
        /// </summary>
        private async Task HandleRefreshTokenRequestAsync(HttpContext context, IClient client)
        {
            var refreshToken = context.Request.Form[OAuth2Consts.Form_RefreshToken].FirstOrDefault();
            if (string.IsNullOrWhiteSpace(refreshToken))
            {
                var errDetail = "refresh token is missing";
                await WriteErrorAsync(context.Response, HttpStatusCode.BadRequest, OAuth2Consts.Err_invalid_request, errDetail);
                return;
            }

            var tokenRequestInfo = await _tokenStore.GetTokenRequestInfoAsync(refreshToken).ConfigureAwait(false);
            if (null == tokenRequestInfo)
            {
                var errDetail = "refresh token is invalid or expired or revoked";
                await WriteErrorAsync(context.Response, HttpStatusCode.BadRequest, OAuth2Consts.Err_invalid_grant, errDetail);
                return;
            }

            if (client.ID != tokenRequestInfo.ClientID)
            {
                var errDetail = $"client id doesn't match, original: '{tokenRequestInfo.ClientID}', current: '{client.ID}'";
                await WriteErrorAsync(context.Response, HttpStatusCode.BadRequest, OAuth2Consts.Err_invalid_request, errDetail);
                return;
            }

            // issue token
            await IssueTokenByRequestInfoAsync(context, GrantType.RefreshToken, client, tokenRequestInfo).ConfigureAwait(false);
        }

        /// <summary>
        /// issue access token and refresh token
        /// </summary>
        protected virtual async Task IssueTokenByRequestInfoAsync(HttpContext context, GrantType grantType, IClient client, TokenRequestInfo tokenRequestInfo)
        {
            // issue token
            var token = await _tokenGenerator.GenerateAccessTokenAsync(
                   context: context
                 , grantType: grantType
                 , client: client
                 , scopes: tokenRequestInfo.Scopes.Split(' ')
                 , username: tokenRequestInfo.Username
             ).ConfigureAwait(false);

            if (client.Grants.Contains(OAuth2Consts.GrantType_RefreshToken))
            {// allowed to use refresh token
                var refreshToken = await _tokenGenerator.GenerateRefreshTokenAsync().ConfigureAwait(false);
                await _tokenStore.SaveRefreshTokenAsync(refreshToken, tokenRequestInfo).ConfigureAwait(false);
                await WriteTokenAsync(context.Response, token, tokenRequestInfo.Scopes, refreshToken).ConfigureAwait(false);
            }
            else
            {// not allowed to use refresh token
                await WriteTokenAsync(context.Response, token, tokenRequestInfo.Scopes).ConfigureAwait(false);

            }
        }

        /// <summary>
        /// write token to browser
        /// </summary>
        protected virtual async Task WriteTokenAsync(HttpResponse response, string token, string scopes, string refreshToken = null)
        {
            response.ContentType = OAuth2Consts.ContentType_Json;
            response.Headers.Add(OAuth2Consts.Header_CacheControl, OAuth2Consts.Header_CacheControl_Value);
            response.Headers.Add(OAuth2Consts.Header_Pragma, OAuth2Consts.Header_Pragma_Value);

            if (null == refreshToken)
            {
                await response.WriteAsync(GenereateTokenJson(token, scopes)).ConfigureAwait(false);
            }
            else
            {
                await response.WriteAsync(GenereateTokenJson(token, refreshToken, scopes)).ConfigureAwait(false);
            }
        }

        /// <summary>
        /// write error to browser
        /// </summary>
        protected virtual async Task WriteErrorAsync(HttpResponse response, HttpStatusCode statusCode, string error, string errorDescription = null)
        {
            errorDescription = errorDescription ?? error;

            _logger.LogWarning(errorDescription);

            response.StatusCode = (int)statusCode;
            response.ContentType = OAuth2Consts.ContentType_Json;
            response.Headers.Add(OAuth2Consts.Header_CacheControl, OAuth2Consts.Header_CacheControl_Value);
            response.Headers.Add(OAuth2Consts.Header_Pragma, OAuth2Consts.Header_Pragma_Value);
            await response.WriteAsync(string.Format(OAuth2Consts.Format_Error, error, errorDescription)).ConfigureAwait(false);
        }

        /// <summary>
        /// generate token json 
        /// </summary>
        protected virtual string GenereateTokenJson(string token, string scopes) => string.Format(OAuth2Consts.Format_Token1, token, AuthServerOptions.ExpiresInSeconds, scopes);

        /// <summary>
        /// generate token json (with refresh token)
        /// </summary>
        protected virtual string GenereateTokenJson(string token, string refreshToken, string scopes) => string.Format(OAuth2Consts.Format_Token2, token, refreshToken, AuthServerOptions.ExpiresInSeconds, scopes);
    }
}
