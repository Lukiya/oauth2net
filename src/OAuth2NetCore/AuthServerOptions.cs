using Microsoft.IdentityModel.Tokens;
using OAuth2NetCore.Security;
using OAuth2NetCore.Store;
using OAuth2NetCore.Token;

namespace OAuth2NetCore
{
    public class AuthServerOptions
    {
        public string SigningAlgorithm { get; set; } = SecurityAlgorithms.RsaSsaPssSha256;
        public IAuthServer AuthServer { get; set; }
        public IClientValidator ClientValidator { get; set; }
        public ITokenGenerator TokenGenerator { get; set; }
        public ITokenClaimGenerator ClaimGenerator { get; set; }
        public ISecurityKeyProvider SecurityKeyProvider { get; set; }
        public IResourceOwnerValidator ResourceOwnerValidator { get; set; }
        public IAuthCodeGenerator AuthCodeGenerator { get; set; }
        public IClientStore ClientStore { get; set; }
        public IAuthCodeStore AuthCodeStore { get; set; }
        public ITokenStore TokenStore { get; set; }
        public IPkceValidator PkceValidator { get; set; }
    }
}