using OAuth2NetCore.Model;
using System.Threading.Tasks;

namespace OAuth2NetCore.Store
{
    public interface ITokenStore
    {
        Task SaveRefreshTokenAsync(string refreshToken, TokenRequestInfo requestInfo, int expireSeconds);
        Task<TokenRequestInfo> GetTokenRequestInfoAsync(string refreshToken);
    }
}
