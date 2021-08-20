using Microsoft.IdentityModel.Tokens;
using OAuth2NetCore;

namespace Microsoft.Extensions.DependencyInjection
{
    public class ResourceOptions
    {
        public string NameClaimType { get; set; } = OAuth2Consts.Claim_Name;
        public string RoleClaimType { get; set; } = OAuth2Consts.Claim_Role;
        public string ValidIssuer { get; set; }
        public string ValidAudience { get; set; }
        public SecurityKey IssuerSigningKey { get; set; }
    }
}