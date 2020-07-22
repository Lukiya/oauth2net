using Microsoft.AspNetCore.Http;
using OAuth2Net.Model;
using System.Collections.Generic;
using System.Security.Claims;
using System.Threading.Tasks;

namespace OAuth2Net.Token
{
    public interface ITokenClaimGenerator
    {
        Task<IList<Claim>> GenerateAsync(HttpContext context, GrantType grantType, IClient client, string[] scopes, string username);
    }
}
