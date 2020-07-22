using Microsoft.Extensions.Logging;
using System.Linq;
using System.Threading.Tasks;

namespace OAuth2Net.Client
{
    public class DefaultClientValidator : IClientValidator
    {
        private readonly ILogger<DefaultAuthServer> _logger;
        private readonly IClientStore _clientStore;

        public DefaultClientValidator(IClientStore clientStore, ILogger<DefaultAuthServer> logger)
        {
            _logger = logger;
            _clientStore = clientStore;
        }

        /// <summary>
        /// Verify client id & secret 
        /// </summary>
        public virtual async Task<MessageResult<IClient>> VerifyClientAsync(string authorzation)
        {
            var mr = new MessageResult<IClient>();

            if (string.IsNullOrWhiteSpace(authorzation))
            {
                mr.MsgCode = OAuth2Consts.Err_invalid_request;
                mr.MsgCodeDescription = "no authorization header";
                _logger.LogDebug(mr.MsgCodeDescription);
                return mr;
            }

            var authArray = authorzation.Split(' ');
            if (authArray.Length != 2 || string.IsNullOrWhiteSpace(authArray[1]))
            {
                mr.MsgCode = OAuth2Consts.Err_invalid_request;
                mr.MsgCodeDescription = "invalid authorization header format";
                _logger.LogDebug(mr.MsgCodeDescription);
                return mr;
            }

            var authStr = Base64Encoder.Decode(authArray[1]);
            authArray = authStr.Split(':');

            if (authArray.Length != 2 || string.IsNullOrWhiteSpace(authArray[0]) || string.IsNullOrWhiteSpace(authArray[1]))
            {
                mr.MsgCode = OAuth2Consts.Err_invalid_request;
                mr.MsgCodeDescription = "invalid authorization header segments length";
                _logger.LogDebug(mr.MsgCodeDescription);
                return mr;
            }

            var client = await _clientStore.VerifyAsync(authArray[0], authArray[1]).ConfigureAwait(false);
            if (client == null)
            {
                mr.MsgCode = OAuth2Consts.Err_invalid_client;
                mr.MsgCodeDescription = "invalid client";
                _logger.LogDebug(mr.MsgCodeDescription);
                return mr;
            }

            mr.Result = client;
            return mr;
        }

        /// <summary>
        /// Verify client id & secret, grant type, scopes
        /// </summary>
        public virtual async Task<MessageResult<IClient>> VerifyClientAsync(string authorzation, string grantType, string scopesStr)
        {
            var mr = new MessageResult<IClient>();

            if (string.IsNullOrWhiteSpace(grantType))
            {
                mr.MsgCode = OAuth2Consts.Err_invalid_request;
                mr.MsgCodeDescription = "grant type is missing";
                _logger.LogDebug(mr.MsgCodeDescription);
                return mr;
            }

            if (string.IsNullOrWhiteSpace(scopesStr))
            {
                mr.MsgCode = OAuth2Consts.Err_invalid_request;
                mr.MsgCodeDescription = "scope is missing";
                _logger.LogDebug(mr.MsgCodeDescription);
                return mr;
            }

            mr = await VerifyClientAsync(authorzation).ConfigureAwait(false);
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
                _logger.LogDebug(mr.MsgCodeDescription);
                return mr;
            }
            if (string.IsNullOrWhiteSpace(responseType))
            {
                mr.MsgCode = OAuth2Consts.Err_invalid_request;
                mr.MsgCodeDescription = "response type is missing";
                _logger.LogDebug(mr.MsgCodeDescription);
                return mr;
            }
            if (string.IsNullOrWhiteSpace(redirectURI))
            {
                mr.MsgCode = OAuth2Consts.Err_invalid_request;
                mr.MsgCodeDescription = "redirect uri is missing";
                _logger.LogDebug(mr.MsgCodeDescription);
                return mr;
            }
            if (string.IsNullOrWhiteSpace(scopesStr))
            {
                mr.MsgCode = OAuth2Consts.Err_invalid_request;
                mr.MsgCodeDescription = "scope is missing";
                _logger.LogDebug(mr.MsgCodeDescription);
                return mr;
            }

            var client = await _clientStore.GetClientAsync(clientID).ConfigureAwait(false);
            if (null == client)
            {
                mr.MsgCode = OAuth2Consts.Err_invalid_client;
                mr.MsgCodeDescription = "invalid client";
                _logger.LogDebug(mr.MsgCodeDescription);
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
                _logger.LogWarning(mr.MsgCodeDescription);
            }
            else if (!client.RedirectUris.Contains(redirectURI))
            {
                mr.MsgCode = OAuth2Consts.Err_access_denied;
                mr.MsgCodeDescription = $"'{redirectURI}' is allowed for '{client.ID}'";
                _logger.LogWarning(mr.MsgCodeDescription);
            }
        }

        protected virtual void ValidateScopes(MessageResult<IClient> mr, IClient client, string scopesStr)
        {
            if (client.Scopes == null)
            {
                mr.MsgCode = OAuth2Consts.Err_invalid_scope;
                mr.MsgCodeDescription = $"no scope is allowed for '{client.ID}'";
                _logger.LogWarning(mr.MsgCodeDescription);
                return;
            }

            var scopeArray = scopesStr.Split(' ');
            var notAllowedScopes = scopeArray.Except(client.Scopes);
            if (notAllowedScopes.Any())
            {
                mr.MsgCode = OAuth2Consts.Err_invalid_scope;
                mr.MsgCodeDescription = $"scope '{string.Join(", ", notAllowedScopes)}' is not allowed for '{client.ID}'";
                _logger.LogWarning(mr.MsgCodeDescription);
            }
        }

        protected virtual void ValidateGrants(MessageResult<IClient> mr, IClient client, string grantType)
        {
            if (client.Grants == null || !client.Grants.Contains(grantType))
            {
                mr.MsgCode = OAuth2Consts.Err_unauthorized_client;
                mr.MsgCodeDescription = $"'{grantType}' grant is not allowed for '{client.ID}'";
                _logger.LogWarning(mr.MsgCodeDescription);
            }
        }

        protected virtual void ValidateResponseType(MessageResult<IClient> mr, IClient client, string responseType)
        {
            if (responseType == OAuth2Consts.ResponseType_Code)
            {
                ValidateGrants(mr, client, OAuth2Consts.GrantType_Code);
            }
            else if (responseType == OAuth2Consts.ResponseType_Token)
            {
                ValidateGrants(mr, client, OAuth2Consts.GrantType_Implicit);
            }
        }
    }
}
