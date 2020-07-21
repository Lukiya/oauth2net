using OAuth2Net.Client;
using OAuth2Net.Security;
using OAuth2Net.Token;

namespace OAuth2Net
{
    public class TokenIssuerOptions
    {
        public int ExpiresInSeconds { get; set; } = 3600;
        public ITokenIssuer TokenIssuer { get; set; }
        public IClientValidator ClientValidator { get; set; }
        public ITokenGenerator TokenGenerator { get; set; }
        public IClaimGenerator ClaimGenerator { get; set; }
        public ISecurityKeyProvider SecurityKeyProvider { get; set; }
        public IClientStore ClientStore { get; set; }
    }
}