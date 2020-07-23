using OAuth2Net.Model;
using System.Threading.Tasks;

namespace OAuth2Net.Store
{
    public interface IAuthCodeStore
    {
        Task<string> SaveAsync(string code, TokenRequestInfo requestInfo);
        Task<TokenRequestInfo> GetAsync(string code);
    }
}
