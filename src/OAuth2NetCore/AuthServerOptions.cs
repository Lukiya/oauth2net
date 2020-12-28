using Microsoft.IdentityModel.Tokens;
using OAuth2NetCore.Security;
using OAuth2NetCore.Store;
using OAuth2NetCore.Token;

namespace OAuth2NetCore
{
    public class AuthServerOptions
    {
        /// <summary>
        /// Required
        /// </summary>
        public ITokenClaimGenerator ClaimGenerator { get; set; }
        /// <summary>
        /// Required
        /// </summary>
        public ISecurityKeyProvider SecurityKeyProvider { get; set; }
        /// <summary>
        /// Required
        /// </summary>
        public IResourceOwnerValidator ResourceOwnerValidator { get; set; }
        /// <summary>
        /// Required
        /// </summary>
        public IClientStore ClientStore { get; set; }
        /// <summary>
        /// Required
        /// </summary>
        public ITokenStore TokenStore { get; set; }

        /// <summary>
        /// Optional
        /// </summary>
        public IAuthServer AuthServer { get; set; }
        /// <summary>
        /// Optional
        /// </summary>
        public IClientValidator ClientValidator { get; set; }
        /// <summary>
        /// Optional
        /// </summary>
        public ITokenGenerator TokenGenerator { get; set; }
        /// <summary>
        /// Optional
        /// </summary>
        public IAuthCodeGenerator AuthCodeGenerator { get; set; }
        /// <summary>
        /// Optional
        /// </summary>
        public IAuthCodeStore AuthCodeStore { get; set; }
        /// <summary>
        /// Optional
        /// </summary>
        public IPkceValidator PkceValidator { get; set; }

        public string SigningAlgorithm { get; set; } = SecurityAlgorithms.RsaSsaPssSha256;
    }
}