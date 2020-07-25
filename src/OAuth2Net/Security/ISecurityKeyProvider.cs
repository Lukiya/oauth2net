using Microsoft.IdentityModel.Tokens;

namespace OAuth2Net.Security
{
    public interface ISecurityKeyProvider
    {
        SecurityKey GetSecurityKey();
    }
}
