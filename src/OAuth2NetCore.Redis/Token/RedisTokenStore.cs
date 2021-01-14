using OAuth2NetCore.Model;
using OAuth2NetCore.Security;
using OAuth2NetCore.Store;
using System;
using System.Text.Json;
using System.Threading.Tasks;

namespace OAuth2NetCore.Redis.Token
{
    public class RedisTokenStore : RedisStore, ITokenStore
    {
        private readonly string _prefix;
        private readonly ISecretEncryptor _secertEncryptor;

        public RedisTokenStore(string connStr, int db = 0, string prefix = "rt:", ISecretEncryptor secretEncryptor = null)
            : base(connStr, db)
        {
            _prefix = prefix;
            _secertEncryptor = secretEncryptor ?? new DefaultSecretEncryptor();
        }

        public async Task SaveRefreshTokenAsync(string refreshToken, TokenInfo requestInfo, int expireSeconds)
        {
            var json = JsonSerializer.Serialize(requestInfo);
            json = _secertEncryptor.Encrypt(json);
            await Database.StringSetAsync(_prefix + refreshToken, json, expiry: TimeSpan.FromSeconds(expireSeconds)).ConfigureAwait(false);

        }

        public async Task<TokenInfo> GetThenRemoveTokenInfoAsync(string refreshToken)
        {
            var json = await Database.StringGetAsync(_prefix + refreshToken).ConfigureAwait(false);
            if (!string.IsNullOrWhiteSpace(json))
            {
                if (_secertEncryptor.TryDecrypt(json, out var decryptedJson))
                {
                    json = decryptedJson;
                    var r = JsonSerializer.Deserialize<TokenInfo>(json);
                    await RemoveRefreshTokenAsync(refreshToken).ConfigureAwait(false);    // remove refresh token after using
                    return r;
                }
            }

            return null;
        }

        public async Task RemoveRefreshTokenAsync(string refreshToken)
        {
            await Database.KeyDeleteAsync(_prefix + refreshToken).ConfigureAwait(false);
        }
    }
}
