using Microsoft.AspNetCore.Http;
using OAuth2Net.Client;
using System.Collections.Generic;
using System.Security.Claims;
using System.Threading.Tasks;

namespace OAuth2Net.Token
{
    public interface IClaimGenerator
    {
        Task<IList<Claim>> GenerateAsync(GrantType grantType, IClient client, string[] scopes);
    }

    public abstract class ClaimGenerator : IClaimGenerator
    {
        protected readonly IHttpContextAccessor HttpContextAccessor;

        public ClaimGenerator(IHttpContextAccessor httpContextAccessor)
        {
            HttpContextAccessor = httpContextAccessor;
        }

        public abstract Task<IList<Claim>> GenerateAsync(GrantType grantType, IClient client, string[] scopes);
    }
}
