using Microsoft.AspNetCore.Http;
using Microsoft.IdentityModel.Tokens;
using OAuth2NetCore.Model;
using OAuth2NetCore.Store;
using System;
using System.Linq;
using System.Net;
using System.Threading.Tasks;

namespace OAuth2NetCore.Security
{
    public class DefaultClientValidator : IClientValidator
    {
        private readonly IClientStore _clientStore;

        public DefaultClientValidator(IClientStore clientStore)
        {
            _clientStore = clientStore;
        }

        /// <summary>
        /// extract client credential from request
        /// </summary>
        public MessageResult<NetworkCredential> ExractClientCredentials(HttpContext context)
        {
            var mr = ExractClientCredentialsFromHeader(context);
            if (mr.IsSuccess) return mr;

            mr = ExractClientCredentialsFromBody(context);
            return mr;
        }

        /// <summary>
        /// extract client credential from request header
        /// </summary>
        protected virtual MessageResult<NetworkCredential> ExractClientCredentialsFromHeader(HttpContext context)
        {
            var authorzation = context.Request.Headers[OAuth2Consts.Header_Authorization].FirstOrDefault();

            var mr = new MessageResult<NetworkCredential>();

            if (string.IsNullOrWhiteSpace(authorzation))
            {
                mr.MsgCode = OAuth2Consts.Err_invalid_request;
                mr.MsgCodeDescription = "no authorization header";
                return mr;
            }

            var authArray = authorzation.Split(OAuth2Consts.Seperator_Scope);
            if (authArray.Length != 2 || string.IsNullOrWhiteSpace(authArray[1]))
            {
                mr.MsgCode = OAuth2Consts.Err_invalid_request;
                mr.MsgCodeDescription = "invalid authorization header format";
                return mr;
            }

            var authStr = Base64UrlEncoder.Decode(authArray[1]);
            authArray = authStr.Split(OAuth2Consts.Seperators_Auth, StringSplitOptions.RemoveEmptyEntries);

            if (authArray.Length != 2 || string.IsNullOrWhiteSpace(authArray[0]) || string.IsNullOrWhiteSpace(authArray[1]))
            {
                mr.MsgCode = OAuth2Consts.Err_invalid_request;
                mr.MsgCodeDescription = "invalid authorization header segments length";
                return mr;
            }

            mr.Result = new NetworkCredential(authArray[0], authArray[1]);
            return mr;
        }

        /// <summary>
        /// extract client credential from request body
        /// </summary>
        protected virtual MessageResult<NetworkCredential> ExractClientCredentialsFromBody(HttpContext context)
        {
            var id = context.Request.Form[OAuth2Consts.Form_ClientID].FirstOrDefault();

            var mr = new MessageResult<NetworkCredential>();

            if (string.IsNullOrWhiteSpace(id))
            {
                mr.MsgCode = OAuth2Consts.Err_invalid_request;
                mr.MsgCodeDescription = "client id is missing";
                return mr;
            }

            var secret = context.Request.Form[OAuth2Consts.Form_ClientSecret].FirstOrDefault();
            if (string.IsNullOrWhiteSpace(secret))
            {
                mr.MsgCode = OAuth2Consts.Err_invalid_request;
                mr.MsgCodeDescription = "client secret is missing";
                return mr;
            }

            mr.Result = new NetworkCredential(id, secret);
            return mr;
        }

        /// <summary>
        /// Verify client id & secret 
        /// </summary>
        public virtual async Task<MessageResult<IClient>> VerifyClientAsync(NetworkCredential credential)
        {
            var mr = new MessageResult<IClient>();

            var client = await _clientStore.GetClientAsync(credential.UserName).ConfigureAwait(false);
            if (client == null)
            {
                mr.MsgCode = OAuth2Consts.Err_invalid_client;
                mr.MsgCodeDescription = "client not exists";
                return mr;
            }

            if (credential.Password != client.Secret)
            {
                mr.MsgCode = OAuth2Consts.Err_invalid_client;
                mr.MsgCodeDescription = "invalid client";
                return mr;
            }

            mr.Result = client;
            return mr;
        }

        /// <summary>
        /// Verify client id & secret, grant type, scopes
        /// </summary>
        public virtual async Task<MessageResult<IClient>> VerifyClientAsync(NetworkCredential credential, string grantType)
        {
            var mr = new MessageResult<IClient>();

            if (string.IsNullOrWhiteSpace(grantType))
            {
                mr.MsgCode = OAuth2Consts.Err_invalid_request;
                mr.MsgCodeDescription = "grant type is missing";
                return mr;
            }

            mr = await VerifyClientAsync(credential).ConfigureAwait(false);
            if (!mr.IsSuccess) return mr;

            ValidateGrants(mr, mr.Result, grantType);
            if (!mr.IsSuccess) return mr;

            return mr;
        }

        /// <summary>
        /// Verify client id & secret, grant type, scopes
        /// </summary>
        public virtual async Task<MessageResult<IClient>> VerifyClientAsync(NetworkCredential credential, string grantType, string scopesStr)
        {
            var mr = new MessageResult<IClient>();

            if (string.IsNullOrWhiteSpace(grantType))
            {
                mr.MsgCode = OAuth2Consts.Err_invalid_request;
                mr.MsgCodeDescription = "grant type is missing";
                return mr;
            }

            if (string.IsNullOrWhiteSpace(scopesStr))
            {
                mr.MsgCode = OAuth2Consts.Err_invalid_request;
                mr.MsgCodeDescription = "scope is missing";
                return mr;
            }

            mr = await VerifyClientAsync(credential).ConfigureAwait(false);
            if (!mr.IsSuccess) return mr;

            ValidateGrants(mr, mr.Result, grantType);
            if (!mr.IsSuccess) return mr;

            ValidateScopes(mr, mr.Result, scopesStr);
            if (!mr.IsSuccess) return mr;

            return mr;
        }

        /// <summary>
        /// Verify client id & secret, response type, scopes, redirect uri
        /// </summary>
        public async Task<MessageResult<IClient>> VerifyClientAsync(string clientID, string responseType, string redirectURI, string scopesStr, string state)
        {
            var mr = new MessageResult<IClient>();
            if (string.IsNullOrWhiteSpace(clientID))
            {
                mr.MsgCode = OAuth2Consts.Err_invalid_request;
                mr.MsgCodeDescription = "client id is missing";
                return mr;
            }
            if (string.IsNullOrWhiteSpace(responseType))
            {
                mr.MsgCode = OAuth2Consts.Err_invalid_request;
                mr.MsgCodeDescription = "response type is missing";
                return mr;
            }
            if (string.IsNullOrWhiteSpace(redirectURI))
            {
                mr.MsgCode = OAuth2Consts.Err_invalid_request;
                mr.MsgCodeDescription = "redirect uri is missing";
                return mr;
            }
            if (string.IsNullOrWhiteSpace(scopesStr))
            {
                mr.MsgCode = OAuth2Consts.Err_invalid_request;
                mr.MsgCodeDescription = "scope is missing";
                return mr;
            }

            var client = await _clientStore.GetClientAsync(clientID).ConfigureAwait(false);
            if (null == client)
            {
                mr.MsgCode = OAuth2Consts.Err_invalid_client;
                mr.MsgCodeDescription = "invalid client";
                return mr;
            }

            ValidateRedirectURIs(mr, client, redirectURI);
            if (!mr.IsSuccess) return mr;

            ValidateScopes(mr, client, scopesStr);
            if (!mr.IsSuccess) return mr;

            ValidateResponseType(mr, client, responseType);
            if (!mr.IsSuccess) return mr;

            mr.Result = client;
            return mr;
        }

        protected virtual void ValidateRedirectURIs(MessageResult<IClient> mr, IClient client, string redirectURI)
        {
            if (client.RedirectUris == null || !client.RedirectUris.Any())
            {
                mr.MsgCode = OAuth2Consts.Err_access_denied;
                mr.MsgCodeDescription = $"no redirect uri is allowed for '{client.ID}'";
            }
            else if (!client.RedirectUris.Contains(redirectURI))
            {
                mr.MsgCode = OAuth2Consts.Err_access_denied;
                mr.MsgCodeDescription = $"'{redirectURI}' is allowed for '{client.ID}'";
            }
        }

        protected virtual void ValidateScopes(MessageResult<IClient> mr, IClient client, string scopesStr)
        {
            if (client.Scopes == null)
            {
                mr.MsgCode = OAuth2Consts.Err_invalid_scope;
                mr.MsgCodeDescription = $"no scope is allowed for '{client.ID}'";
                return;
            }

            var scopeArray = scopesStr.Split(OAuth2Consts.Seperator_Scope);
            var notAllowedScopes = scopeArray.Except(client.Scopes);
            if (notAllowedScopes.Any())
            {
                mr.MsgCode = OAuth2Consts.Err_invalid_scope;
                mr.MsgCodeDescription = $"scope '{string.Join(", ", notAllowedScopes)}' is not allowed for '{client.ID}'";
            }
        }

        protected virtual void ValidateGrants(MessageResult<IClient> mr, IClient client, string grantType)
        {
            if (client.Grants == null || !client.Grants.Contains(grantType))
            {
                mr.MsgCode = OAuth2Consts.Err_unauthorized_client;
                mr.MsgCodeDescription = $"'{grantType}' grant is not allowed for '{client.ID}'";
            }
        }

        protected virtual void ValidateResponseType(MessageResult<IClient> mr, IClient client, string responseType)
        {
            if (responseType == OAuth2Consts.ResponseType_Code)
            {
                ValidateGrants(mr, client, OAuth2Consts.GrantType_AuthorizationCode);
            }
            else if (responseType == OAuth2Consts.ResponseType_Token)
            {
                ValidateGrants(mr, client, OAuth2Consts.GrantType_Implicit);
            }
        }
    }
}
