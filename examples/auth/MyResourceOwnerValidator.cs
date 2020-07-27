using OAuth2NetCore.Security;
using System.Threading.Tasks;

namespace auth
{
    /// <summary>
    /// Just for testing, DO NOT USE
    /// </summary>
    public class MyResourceOwnerValidator : IResourceOwnerValidator
    {
        public Task<bool> VertifyAsync(string username, string password)
        {
            return Task.FromResult(username == password);
        }
    }
}
