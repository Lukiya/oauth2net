using System.Threading.Tasks;

namespace OAuth2Net.Security
{
    public interface IResourceOwnerValidator
    {
        Task<bool> VertifyAsync(string username, string password);
    }
}
