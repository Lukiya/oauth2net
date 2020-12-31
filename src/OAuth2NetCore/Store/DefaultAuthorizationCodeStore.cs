using OAuth2NetCore.Model;
using System.Threading.Tasks;

namespace OAuth2NetCore.Store
{
    public class DefaultAuthCodeStore : IAuthCodeStore
    {
        static AutoCleanDictionary<string, TokenInfo> _dic = new AutoCleanDictionary<string, TokenInfo>(60, 60);

        public Task SaveAsync(string code, TokenInfo requestInfo)
        {
            _dic.TryAdd(code, requestInfo);
            return Task.CompletedTask;
        }

        public Task<TokenInfo> GetThenRemoveAsync(string code)
        {
            _dic.TryRemove(code, out var o);
            return Task.FromResult(o);
        }
    }
}
