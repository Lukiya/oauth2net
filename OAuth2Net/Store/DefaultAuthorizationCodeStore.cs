using OAuth2Net.Model;
using System;
using System.Threading.Tasks;

namespace OAuth2Net.Store
{
    public class DefaultAuthorizationCodeStore : IAuthorizationCodeStore
    {
        static AutoCleanDictionary<string, AuthCodePayload> _dic = new AutoCleanDictionary<string, AuthCodePayload>(60, 60);

        public Task<string> GenerateAsync(AuthCodePayload payload)
        {
            var code = Guid.NewGuid().ToString("N") + Guid.NewGuid().ToString("N");
            _dic.TryAdd(code, payload);
            return Task.FromResult(code);
        }

        public Task<AuthCodePayload> GetAsync(string code)
        {
            _dic.TryRemove(code, out var payload);
            return Task.FromResult(payload);
        }
    }
}
