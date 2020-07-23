using Newtonsoft.Json;
using OAuth2Net.Model;
using OAuth2Net.Store;
using System;
using System.Threading.Tasks;

namespace OAuth2Net.Redis.Token
{
    public class RedisTokenStore : RedisBase, ITokenStore
    {
        private readonly string _prefix = "zzz_";
        private readonly int _refreshTokenExpireDays;

        public RedisTokenStore(string connStr, int db = 0, int refreshTokenExpireHours = 24 * 14, string prefix = "zzz_")
            : base(connStr, db)
        {
            _refreshTokenExpireDays = refreshTokenExpireHours;
            _prefix = prefix;
        }

        public async Task SaveRefreshTokenAsync(string refreshToken, TokenRequestInfo requestInfo)
        {
            var json = JsonConvert.SerializeObject(requestInfo);
            await Database.StringSetAsync(_prefix + refreshToken, json, expiry: TimeSpan.FromDays(_refreshTokenExpireDays)).ConfigureAwait(false);
        }

        public async Task<TokenRequestInfo> GetTokenRequestInfoAsync(string refreshToken)
        {
            var json = await Database.StringGetAsync(_prefix + refreshToken).ConfigureAwait(false);
            if (!string.IsNullOrWhiteSpace(json))
            {
                var r = JsonConvert.DeserializeObject<TokenRequestInfo>(json);
                await Database.KeyDeleteAsync(_prefix + refreshToken).ConfigureAwait(false);    // remove refresh token after using
                return r;
            }
            else
            {
                return null;
            }
        }
    }
}
