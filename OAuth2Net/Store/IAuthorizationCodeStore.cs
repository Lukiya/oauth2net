using OAuth2Net.Model;
using System.Threading.Tasks;

namespace OAuth2Net.Store
{
    public interface IAuthorizationCodeStore
    {
        Task<string> GenerateAsync(AuthCodePayload payload);
        Task<AuthCodePayload> GetAsync(string code);
    }
}
