using Microsoft.AspNetCore.Http;
using OAuth2Net.Model;
using System.Threading.Tasks;

namespace OAuth2Net.Token
{
    public interface ITokenGenerator
    {
        Task<string> GenerateAsync(HttpContext context, GrantType grantType, IClient client, string[] scopes, string username);
    }
}
