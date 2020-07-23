using Newtonsoft.Json;
using OAuth2Net.Model;
using OAuth2Net.Security;
using OAuth2Net.Store;
using StackExchange.Redis;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace OAuth2Net.Redis.Client
{
    public class RedisClientStore : RedisBase, IClientStore
    {
        private readonly string _key;
        private readonly ISecertHash _secertHash;

        public RedisClientStore(string connStr, string key, int db = 0, ISecertHash secertHash = null)
            : base(connStr, db)
        {
            _key = key;
            _secertHash = secertHash ?? new NoSecertHash();
        }

        public IClient GetClient(string clientID)
        {
            var json = Database.HashGet(_key, clientID);
            return JsonConvert.DeserializeObject<Model.Client>(json);
        }
        public async Task<IClient> GetClientAsync(string clientID)
        {
            var json = await Database.HashGetAsync(_key, clientID).ConfigureAwait(false);
            if (json.IsNull)
            {
                return null;
            }
            return JsonConvert.DeserializeObject<Model.Client>(json.ToString());
        }

        public IDictionary<string, IClient> GetClients()
        {
            var hashEntries = Database.HashGetAll(_key);
            return hashEntries.ToDictionary(x => x.ToString(), x => (IClient)JsonConvert.DeserializeObject<Model.Client>(x.ToString()));
        }
        public async Task<IDictionary<string, IClient>> GetClientsAsync()
        {
            var hashEntries = await Database.HashGetAllAsync(_key).ConfigureAwait(false);
            return hashEntries.ToDictionary(x => x.Name.ToString(), x => (IClient)JsonConvert.DeserializeObject<Model.Client>(x.Value.ToString()));
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
