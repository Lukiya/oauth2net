using Microsoft.AspNetCore.Http;
using OAuth2NetCore;
using OAuth2NetCore.Model;
using OAuth2NetCore.Token;
using System.Collections.Generic;
using System.Security.Claims;
using System.Threading.Tasks;

namespace auth
{
    public class MyTokenClaimGenerator : ITokenClaimGenerator
    {
        public Task<IList<Claim>> GenerateAsync(HttpContext context, GrantType grantType, IClient client, string[] scopes, string username)
        {
            var claims = new List<Claim>();
            claims.Add(new Claim(OAuth2Consts.Claim_Name, username));

            // add issuer, this example just use http address as issuer, you can implement your own logic
            var issuer = $"{context.Request.Scheme}://{context.Request.Host}";
            claims.Add(new Claim(OAuth2Consts.Claim_Issuer, issuer));

            // add audiences, this example just use client requested scopes as audiences
            foreach (var scope in scopes)
            {
                claims.Add(new Claim(OAuth2Consts.Claim_Audience, scope));
            }

            if (grantType == GrantType.ClientCredentials)
            {
                claims.Add(new Claim(OAuth2Consts.Claim_Role, "1"));
            }
            else
            {
                claims.Add(new Claim(OAuth2Consts.Claim_Role, "4"));
            }

            return Task.FromResult<IList<Claim>>(claims);
        }
    }
}
