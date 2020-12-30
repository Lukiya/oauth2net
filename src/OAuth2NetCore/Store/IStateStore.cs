using System.Threading.Tasks;

namespace OAuth2NetCore.Store
{
    public interface IStateStore
    {
        Task AddAsync(string key, string value, int expireSeconds = 60);
        Task<string> RemoveAsync(string key);
    }
}
