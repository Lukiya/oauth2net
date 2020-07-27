using OAuth2NetCore.Model;
using System.Threading.Tasks;

namespace OAuth2NetCore.Store
{
    public class DefaultAuthCodeStore : IAuthCodeStore
    {
        static AutoCleanDictionary<string, TokenRequestInfo> _dic = new AutoCleanDictionary<string, TokenRequestInfo>(60, 60);

        public Task<string> SaveAsync(string code, TokenRequestInfo requestInfo)
        {
            _dic.TryAdd(code, requestInfo);
            return Task.FromResult(code);
        }

        public Task<TokenRequestInfo> GetAsync(string code)
        {
            _dic.TryRemove(code, out var o);
            return Task.FromResult(o);
        }
    }
}
