using Microsoft.Extensions.Logging;
using OAuth2Net.Client;
using System.Linq;
using System.Threading.Tasks;

namespace OAuth2Net.Client
{
    public interface IClientValidator
    {
        Task<MessageResult<IClient>> VerifyClientAsync(string authorzation);
        Task<MessageResult<IClient>> VerifyClientAsync(string authorzation, string grantType, string scopes);
    }

    public class ClientValidator : IClientValidator
    {
        private readonly ILogger<TokenIssuer> _logger;
        private readonly IClientStore _clientStore;

        public ClientValidator(IClientStore clientStore, ILogger<TokenIssuer> logger)
        {
            _logger = logger;
            _clientStore = clientStore;
        }
        public async Task<MessageResult<IClient>> VerifyClientAsync(string authorzation)
        {
            var r = new MessageResult<IClient>();

            if (string.IsNullOrWhiteSpace(authorzation))
            {
                r.Message = "no authorization header";
                _logger.LogDebug(r.Message);
                return r;
            }

            var authArray = authorzation.Split(' ');
            if (authArray.Length != 2 || string.IsNullOrWhiteSpace(authArray[1]))
            {
                r.Message = "invalid authorization header";
                _logger.LogDebug(r.Message);
                return r;
            }

            var authStr = Base64Encoder.Decode(authArray[1]);
            authArray = authStr.Split(':');

            if (authArray.Length != 2 || string.IsNullOrWhiteSpace(authArray[0]) || string.IsNullOrWhiteSpace(authArray[1]))
            {
                r.Message = "invalid authorization header";
                _logger.LogDebug(r.Message);
                return r;
            }

            var client = await _clientStore.VerifyAsync(authArray[0], authArray[1]).ConfigureAwait(false);
            if (client == null)
            {
                r.Message = "invalid client";
                _logger.LogDebug(r.Message);
                return r;
            }

            r.Result = client;
            return r;
        }

        public async Task<MessageResult<IClient>> VerifyClientAsync(string authorzation, string grantType, string scopes)
        {
            var r = new MessageResult<IClient>();

            if (string.IsNullOrWhiteSpace(grantType))
            {
                r.Message = "no grant type";
                _logger.LogDebug(r.Message);
                return r;
            }

            if (string.IsNullOrWhiteSpace(scopes))
            {
                r.Message = "no scope";
                _logger.LogDebug(r.Message);
                return r;
            }

            r = await VerifyClientAsync(authorzation).ConfigureAwait(false);
            if (!r.IsSuccess)
                return r;

            if (r.Result.Grants == null || !r.Result.Grants.Contains(grantType))
            {
                r.Message = $"'{grantType}' grant is not allowed for '{r.Result.ID}'";
                _logger.LogDebug(r.Message);
                return r;
            }

            if (r.Result.Scopes == null)
            {
                r.Message = $"no scope is allowed for '{r.Result.ID}'";
                _logger.LogDebug(r.Message);
                return r;
            }

            var scopeArray = scopes.Split(' ');
            var notAllowedScopes = scopeArray.Except(r.Result.Scopes);
            if (notAllowedScopes.Any())
            {
                r.Message = $"scope '{string.Join(", ", notAllowedScopes)}' is not allowed for '{r.Result.ID}'";
                _logger.LogDebug(r.Message);
            }

            return r;
        }
    }
}
