using System;
using System.Threading.Tasks;

namespace OAuth2Net.Token
{
    public class DefaultAuthCodeGenerator : IAuthCodeGenerator
    {
        public Task<string> GenerateAsync()
        {
            return Task.FromResult(Guid.NewGuid().ToString("N") + Guid.NewGuid().ToString("N"));
        }
    }
}
