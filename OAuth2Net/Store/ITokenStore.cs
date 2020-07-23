using OAuth2Net.Model;
using System.Threading.Tasks;

namespace OAuth2Net.Store
{
    public interface ITokenStore
    {
        Task SaveRefreshTokenAsync(string refreshToken, TokenRequestInfo requestInfo);
        Task<TokenRequestInfo> GetTokenRequestInfoAsync(string refreshToken);
    }
}
