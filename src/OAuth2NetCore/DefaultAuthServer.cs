using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using OAuth2NetCore.Client;
using OAuth2NetCore.Model;
using OAuth2NetCore.Security;
using OAuth2NetCore.Store;
using OAuth2NetCore.Token;
using System;
using System.Linq;
using System.Net;
using System.Threading.Tasks;

namespace OAuth2NetCore
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
        private readonly IPkceValidator _pkceValidator;
        private readonly IConfiguration _configuration;

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
            , IPkceValidator pkceValidator
            , IConfiguration configuration
        )
        {
            _clientValidator = clientValidator;
            _tokenGenerator = tokenGenerator;
            _resourceOwnerValidator = resourceOwnerValidator;
            _logger = logger;
            _authCodeStore = authCodeStore;
            _tokenStore = tokenStore;
            _authCodeGenerator = authCodeGenerator;
            _pkceValidator = pkceValidator;
            _configuration = configuration;

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
                // user not login, redirect to login page
                await context.ChallengeAsync().ConfigureAwait(false);
                return;
            }

            string code;
            // pkce check
            var pkceRequired = _configuration.GetValue<bool>(OAuth2Consts.Config_OAuth_PkceRequired);
            if (!pkceRequired)
            {
                // pkce not required, just issue code
                code = await _authCodeGenerator.GenerateAsync().ConfigureAwait(false);
                await _authCodeStore.SaveAsync(code,
                    new TokenRequestInfo
                    {
                        ClientID = client.ID,
                        Scopes = scopesStr,
                        RedirectUri = redirectUri,
                        Username = context.User.Identity.Name,
                    }
                ).ConfigureAwait(false);

                context.Response.Redirect($"{redirectUri}?{OAuth2Consts.Form_Code}={code}&{OAuth2Consts.Form_State}={Uri.EscapeDataString(state)}");
                return;
            }

            // pkce required
            var codeChanllenge = context.Request.Query[OAuth2Consts.Form_CodeChallenge].FirstOrDefault();
            if (string.IsNullOrWhiteSpace(codeChanllenge))
            {// client didn't provide pkce chanllenge, write error
                await WriteErrorAsync(context.Response, HttpStatusCode.BadRequest, OAuth2Consts.Err_invalid_request, "code chanllenge is required.").ConfigureAwait(false);
                return;
            }
            // client provided pkce chanllenge
            var codeChanllengeMethod = context.Request.Query[OAuth2Consts.Form_CodeChallengeMethod].FirstOrDefault();
            if (string.IsNullOrWhiteSpace(codeChanllengeMethod))
            {
                codeChanllengeMethod = OAuth2Consts.Pkce_Plain;
            }
            else if (codeChanllengeMethod != OAuth2Consts.Pkce_Plain && codeChanllengeMethod != OAuth2Consts.Pkce_S256)
            {
                await WriteErrorAsync(context.Response, HttpStatusCode.BadRequest, OAuth2Consts.Err_invalid_request, "transform algorithm not supported").ConfigureAwait(false);
                return;
            }

            // issue code with chanllenge
            code = await _authCodeGenerator.GenerateAsync().ConfigureAwait(false);
            await _authCodeStore.SaveAsync(code,
                new TokenRequestInfo
                {
                    ClientID = client.ID,
                    Scopes = scopesStr,
                    RedirectUri = redirectUri,
                    Username = context.User.Identity.Name,
                    CodeChanllenge = codeChanllenge,
                    CodeChanllengeMethod = codeChanllengeMethod,
                }
            ).ConfigureAwait(false);

            context.Response.Redirect($"{redirectUri}?{OAuth2Consts.Form_Code}={code}&{OAuth2Consts.Form_State}={Uri.EscapeDataString(state)}&{OAuth2Consts.Form_CodeChallenge}={Uri.EscapeDataString(codeChanllenge)}&{OAuth2Consts.Form_CodeChallengeMethod}={codeChanllengeMethod}");
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
                    , scopes: scopesStr.Split(OAuth2Consts.Seperator_Scope)
                    , username: context.User.Identity.Name
                ).ConfigureAwait(false);

                context.Response.Redirect($"{redirectURI}?{OAuth2Consts.Form_AccessToken}={Uri.EscapeDataString(token)}&{OAuth2Consts.Form_TokenType}=Bearer&{OAuth2Consts.Form_ExpiresIn}={client.AccessTokenExpireSeconds}&{OAuth2Consts.Form_Scope}={Uri.EscapeDataString(scopesStr)}&{OAuth2Consts.Form_State}={Uri.EscapeDataString(state)}");
            }
        }

        /// <summary>
        /// handle token reqeust
        /// </summary>
        protected virtual async Task HandleTokenRequestAsync(HttpContext context)
        {
            // get parametes from request
            var grantTypeStr = context.Request.Form[OAuth2Consts.Form_GrantType].FirstOrDefault();
            var scopesStr = context.Request.Form[OAuth2Consts.Form_Scope].FirstOrDefault();

            var clientCredentialsResult = _clientValidator.ExractClientCredentials(context);
            if (!clientCredentialsResult.IsSuccess)
            {
                await WriteErrorAsync(context.Response, HttpStatusCode.BadRequest, clientCredentialsResult.MsgCode, clientCredentialsResult.MsgCodeDescription).ConfigureAwait(false);
                return;
            }

            // verify client
            MessageResult<IClient> clientVerifyResult;
            if (grantTypeStr == OAuth2Consts.GrantType_AuthorizationCode)
            {
                // auth code grant doesn't post scopes 
                clientVerifyResult = await _clientValidator.VerifyClientAsync(clientCredentialsResult.Result, grantTypeStr).ConfigureAwait(false);
            }
            else
            {
                // other scopes must post scopes
                clientVerifyResult = await _clientValidator.VerifyClientAsync(clientCredentialsResult.Result, grantTypeStr, scopesStr).ConfigureAwait(false);
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
                              , scopes: scopesStr.Split(OAuth2Consts.Seperator_Scope)
                              , username: client.ID
                          ).ConfigureAwait(false);

            await WriteTokenAsync(context.Response, token, scopesStr, client.AccessTokenExpireSeconds).ConfigureAwait(false);
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


            var tokenRequestInfo = await _authCodeStore.GetThenRemoveAsync(code).ConfigureAwait(false);
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

            // pkce check
            var pkceRequired = _configuration.GetValue<bool>(OAuth2Consts.Config_OAuth_PkceRequired);
            if (!pkceRequired)
            {
                // issue token
                await IssueTokenByRequestInfoAsync(context, GrantType.AuthorizationCode, client, tokenRequestInfo).ConfigureAwait(false);
                return;
            }

            var codeVierifier = context.Request.Form[OAuth2Consts.Form_CodeVerifier].FirstOrDefault();
            if (string.IsNullOrWhiteSpace(codeVierifier))
            {
                // client didn't provide code verifier, write error
                var errDetail = "code verifier is missing";
                await WriteErrorAsync(context.Response, HttpStatusCode.BadRequest, OAuth2Consts.Err_invalid_request, errDetail);
                return;
            }

            if (!_pkceValidator.Verify(codeVierifier, tokenRequestInfo.CodeChanllenge, tokenRequestInfo.CodeChanllengeMethod))
            {
                var errDetail = "code verifier is invalid";
                await WriteErrorAsync(context.Response, HttpStatusCode.BadRequest, OAuth2Consts.Err_invalid_grant, errDetail);
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
                 , scopes: tokenRequestInfo.Scopes.Split(OAuth2Consts.Seperator_Scope)
                 , username: tokenRequestInfo.Username
             ).ConfigureAwait(false);

            if (client.Grants.Contains(OAuth2Consts.GrantType_RefreshToken))
            {// allowed to use refresh token
                var refreshToken = await _tokenGenerator.GenerateRefreshTokenAsync().ConfigureAwait(false);
                await _tokenStore.SaveRefreshTokenAsync(refreshToken, tokenRequestInfo, client.RefreshTokenExpireSeconds).ConfigureAwait(false);
                await WriteTokenAsync(context.Response, token, tokenRequestInfo.Scopes, client.AccessTokenExpireSeconds, refreshToken).ConfigureAwait(false);
            }
            else
            {// not allowed to use refresh token
                await WriteTokenAsync(context.Response, token, tokenRequestInfo.Scopes, client.AccessTokenExpireSeconds).ConfigureAwait(false);

            }
        }

        /// <summary>
        /// write token to browser
        /// </summary>
        protected virtual async Task WriteTokenAsync(HttpResponse response, string token, string scopes, int expireSeonds, string refreshToken = null)
        {
            response.ContentType = OAuth2Consts.ContentType_Json;
            response.Headers.Add(OAuth2Consts.Header_CacheControl, OAuth2Consts.Header_CacheControl_Value);
            response.Headers.Add(OAuth2Consts.Header_Pragma, OAuth2Consts.Header_Pragma_Value);

            if (null == refreshToken)
            {
                await response.WriteAsync(GenereateTokenJson(token, scopes, expireSeonds)).ConfigureAwait(false);
            }
            else
            {
                await response.WriteAsync(GenereateTokenJson(token, refreshToken, scopes, expireSeonds)).ConfigureAwait(false);
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
        protected virtual string GenereateTokenJson(string token, string scopes, int expireSeonds) => string.Format(OAuth2Consts.Format_Token1, token, expireSeonds, scopes);

        /// <summary>
        /// generate token json (with refresh token)
        /// </summary>
        protected virtual string GenereateTokenJson(string token, string refreshToken, string scopes, int expireSeonds) => string.Format(OAuth2Consts.Format_Token2, token, refreshToken, expireSeonds, scopes);
    }
}
