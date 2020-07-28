using OAuth2NetCore.Model;
using System.Threading.Tasks;

namespace OAuth2NetCore.Store
{
    public interface IAuthCodeStore
    {
        Task SaveAsync(string code, TokenRequestInfo requestInfo);
        Task<TokenRequestInfo> GetThenRemoveAsync(string code);
    }
}
