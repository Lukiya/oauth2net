using Microsoft.IdentityModel.Tokens;
using OAuth2Net.Client;
using OAuth2Net.Security;
using OAuth2Net.Store;
using OAuth2Net.Token;

namespace OAuth2Net
{
    public class AuthServerOptions
    {
        public int ExpiresInSeconds { get; set; } = 3600;
        public string SigningAlgorithm { get; set; } = SecurityAlgorithms.RsaSsaPssSha256;
        public IAuthServer AuthServer { get; set; }
        public IClientValidator ClientValidator { get; set; }
        public ITokenGenerator TokenGenerator { get; set; }
        public ITokenClaimGenerator ClaimGenerator { get; set; }
        public ISecurityKeyProvider SecurityKeyProvider { get; set; }
        public IResourceOwnerValidator ResourceOwnerValidator { get; set; }
        public IClientStore ClientStore { get; set; }
        public IAuthorizationCodeStore AuthorizationCodeStore { get; set; }
    }
}