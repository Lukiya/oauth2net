using System.Threading.Tasks;

namespace OAuth2Net.Security
{
    public interface IResourceOwnerValidator
    {
        Task<MessageResult<bool>> VertifyAsync(string username, string password);
    }
}
