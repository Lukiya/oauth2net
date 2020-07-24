using Microsoft.AspNetCore.Http;
using OAuth2Net.Model;
using System.Net;
using System.Threading.Tasks;

namespace OAuth2Net.Client
{
    public interface IClientValidator
    {
        MessageResult<NetworkCredential> ExractClientCredentials(HttpContext context);

        Task<MessageResult<IClient>> VerifyClientAsync(NetworkCredential credential);
        Task<MessageResult<IClient>> VerifyClientAsync(NetworkCredential credential, string grantType);
        Task<MessageResult<IClient>> VerifyClientAsync(NetworkCredential credential, string grantType, string scopesStr);
        Task<MessageResult<IClient>> VerifyClientAsync(string clientID, string responseType, string redirectURI, string scopesStr, string state);
    }
}
