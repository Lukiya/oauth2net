using OAuth2NetCore.Model;
using System.Threading.Tasks;

namespace OAuth2NetCore.Store
{
    public interface IAuthCodeStore
    {
        Task<string> SaveAsync(string code, TokenRequestInfo requestInfo);
        Task<TokenRequestInfo> GetAsync(string code);
    }
}
