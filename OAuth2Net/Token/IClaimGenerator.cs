using Microsoft.AspNetCore.Http;
using OAuth2Net.Client;
using System.Collections.Generic;
using System.Security.Claims;
using System.Threading.Tasks;

namespace OAuth2Net.Token
{
    public interface IClaimGenerator
    {
        Task<IList<Claim>> GenerateAsync(HttpContext context, GrantType grantType, IClient client, string[] scopes, string username);
    }
}
