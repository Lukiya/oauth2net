using StackExchange.Redis;
using System;

namespace OAuth2Net.Redis
{
    public abstract class RedisBase
    {
        private readonly Lazy<IDatabase> _lazyDatabase;
        protected virtual IDatabase Database => _lazyDatabase.Value;

        public RedisBase(string connStr, int db)
        {
            _lazyDatabase = new Lazy<IDatabase>(() =>
            {
                var a = ConnectionMultiplexer.Connect(connStr);
                return a.GetDatabase(db);
            });
        }
    }
}
