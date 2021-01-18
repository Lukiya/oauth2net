using Microsoft.IdentityModel.JsonWebTokens;
using OAuth2NetCore.Model;
using System.Threading.Tasks;

namespace OAuth2NetCore.Store
{
    public interface ITokenDTOStore
    {
        Task<JsonWebToken> SaveTokenDTOAsync(string json);
        Task<TokenDTO> GetTokenDTOAsync();
    }
}
