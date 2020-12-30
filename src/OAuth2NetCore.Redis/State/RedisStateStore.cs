using OAuth2NetCore.Store;
using System;
using System.Threading.Tasks;

namespace OAuth2NetCore.Redis.State
{
    public class RedisStateStore : RedisStore, IStateStore
    {
        private readonly string _prefix;

        public RedisStateStore(string connStr, int db = 0, string prefix = "st:")
            : base(connStr, db)
        {
            _prefix = prefix;
        }

        public async Task AddAsync(string key, string value, int expireSeconds)
        {
            if (expireSeconds > 0)
            {
                await Database.StringSetAsync(_prefix + key, value, expiry: TimeSpan.FromSeconds(expireSeconds)).ConfigureAwait(false);
            }
            else
            {
                await Database.StringSetAsync(_prefix + key, value).ConfigureAwait(false);
            }
        }

        public async Task<string> RemoveAsync(string key)
        {
            key = _prefix + key;
            var value = await Database.StringGetAsync(key).ConfigureAwait(false);
            if (!string.IsNullOrWhiteSpace(value))
            {
                await Database.KeyDeleteAsync(key).ConfigureAwait(false);    // remove refresh token after using
            }

            return value;
        }
    }
}
