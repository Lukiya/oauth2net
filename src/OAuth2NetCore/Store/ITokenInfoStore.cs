using OAuth2NetCore.Model;
using System.Threading.Tasks;

namespace OAuth2NetCore.Store
{
    public interface ITokenInfoStore
    {
        Task SaveRefreshTokenAsync(string refreshToken, TokenInfo requestInfo, int expireSeconds);
        Task<TokenInfo> GetThenRemoveTokenInfoAsync(string refreshToken);
        Task RemoveRefreshTokenAsync(string refreshToken);
    }
}
