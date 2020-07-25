using System.Threading.Tasks;

namespace OAuth2Net.Token
{
    public interface IAuthCodeGenerator
    {
        Task<string> GenerateAsync();
    }
}
