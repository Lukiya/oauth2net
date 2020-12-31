using OAuth2NetCore.Model;
using System.Threading.Tasks;

namespace OAuth2NetCore.Store
{
    public interface ITokenStore
    {
        Task SaveRefreshTokenAsync(string refreshToken, TokenInfo requestInfo, int expireSeconds);
        Task<TokenInfo> GetTokenInfoAsync(string refreshToken);
    }
}
