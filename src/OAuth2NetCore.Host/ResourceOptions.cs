using Microsoft.IdentityModel.Tokens;

namespace Microsoft.Extensions.DependencyInjection
{
    public class ResourceOptions
    {
        public string NameClaimType { get; set; } = "name";
        public string RoleClaimType { get; set; } = "role";
        public SecurityKey IssuerSigningKey { get; set; }
        public string ValidIssuer { get; set; }
        public string ValidAudience { get; set; }
    }
}