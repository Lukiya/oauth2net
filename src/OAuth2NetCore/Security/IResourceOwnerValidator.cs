using System.Threading.Tasks;

namespace OAuth2NetCore.Security
{
    public interface IResourceOwnerValidator
    {
        Task<bool> VertifyAsync(string username, string password);
    }
}
