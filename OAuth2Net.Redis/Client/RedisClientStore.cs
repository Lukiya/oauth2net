using System;
using System.Linq;
using System.Collections.Generic;
using OAuth2Net.Client;
using OAuth2Net.Security;
using StackExchange.Redis;
using Newtonsoft.Json;
using System.Threading.Tasks;

namespace OAuth2Net.Redis.Client
{
    public class RedisClientStore : IClientStore
    {
        private readonly string _key;
        private readonly ISecertHash _secertHash;
        private readonly Lazy<IConnectionMultiplexer> _lazyConnectionMultiplexer;
        private IConnectionMultiplexer _ConnectionMultiplexer => _lazyConnectionMultiplexer.Value;

        private readonly Lazy<IDatabase> _lazyDatabase;
        protected virtual IDatabase _Database => _lazyDatabase.Value;

        public RedisClientStore(string connStr, string key, int db = 0, ISecertHash secertHash = null)
        {
            _key = key;
            _secertHash = secertHash ?? new NoSecertHash();
            _lazyConnectionMultiplexer = new Lazy<IConnectionMultiplexer>(() =>
            {
                return ConnectionMultiplexer.Connect(connStr);
            });

            _lazyDatabase = new Lazy<IDatabase>(() => _ConnectionMultiplexer.GetDatabase(db));
        }

        public IClient GetClient(string clientID)
        {
            var json = _Database.HashGet(_key, clientID);
            return JsonConvert.DeserializeObject<OAuth2Net.Client.Client>(json);
        }
        public async Task<IClient> GetClientAsync(string clientID)
        {
            var json = await _Database.HashGetAsync(_key, clientID).ConfigureAwait(false);
            if (json.IsNull)
            {
                return null;
            }
            return JsonConvert.DeserializeObject<OAuth2Net.Client.Client>(json.ToString());
        }

        public IDictionary<string, IClient> GetClients()
        {
            var hashEntries = _Database.HashGetAll(_key);
            return hashEntries.ToDictionary(x => x.ToString(), x => (IClient)JsonConvert.DeserializeObject<OAuth2Net.Client.Client>(x.ToString()));
        }
        public async Task<IDictionary<string, IClient>> GetClientsAsync()
        {
            var hashEntries = await _Database.HashGetAllAsync(_key).ConfigureAwait(false);
            return hashEntries.ToDictionary(x => x.Name.ToString(), x => (IClient)JsonConvert.DeserializeObject<OAuth2Net.Client.Client>(x.Value.ToString()));
        }

        public IClient Verify(string clientID, string clientSecret)
        {
            var client = GetClient(clientID);
            if (client != null && client.Secret == _secertHash.Hash(clientSecret))
            {
                return client;
            }

            return null;
        }
        public async Task<IClient> VerifyAsync(string clientID, string clientSecret)
        {
            var client = await GetClientAsync(clientID).ConfigureAwait(false);
            if (client != null && client.Secret == _secertHash.Hash(clientSecret))
            {
                return client;
            }

            return null;
        }
    }
}
