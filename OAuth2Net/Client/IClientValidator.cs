using System.Threading.Tasks;

namespace OAuth2Net.Client
{
    public interface IClientValidator
    {
        Task<MessageResult<IClient>> VerifyClientAsync(string authorzation);
        Task<MessageResult<IClient>> VerifyClientAsync(string authorzation, string grantType, string scopesStr);
        Task<MessageResult<IClient>> VerifyClientAsync(string clientID, string responseType, string redirectURI, string scopesStr, string state);
    }
}
