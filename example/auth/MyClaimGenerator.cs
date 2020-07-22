using Microsoft.AspNetCore.Http;
using OAuth2Net;
using OAuth2Net.Client;
using OAuth2Net.Token;
using System.Collections.Generic;
using System.Security.Claims;
using System.Threading.Tasks;

namespace auth
{
    public class MyClaimGenerator : DefaultClaimGeneratorBase
    {
        public override Task<IList<Claim>> GenerateAsync(HttpContext context, GrantType grantType, IClient client, string[] scopes, string username)
        {
            var claims = new List<Claim>();
            claims.Add(new Claim(OAuth2Consts.Claim_Name, username));

            // add issuer, this example just use http address as issuer, you can implement your own logic
            var issuer = $"{context.Request.Scheme}://{context.Request.Host}";
            claims.Add(new Claim(OAuth2Consts.Claim_Issuer, issuer));

            // add audiences, this example just use user requested scopes as audiences
            foreach (var scope in scopes)
            {
                claims.Add(new Claim(OAuth2Consts.Claim_Audience, scope));
            }

            if (grantType == GrantType.ClientCredentials)
            {
                claims.Add(new Claim(OAuth2Consts.Claim_Role, "1"));
            }

            return Task.FromResult<IList<Claim>>(claims);
        }
    }
}
