using Microsoft.AspNetCore.Http;
using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace OAuth2Net.Security
{
    public interface IClaimGenerator
    {
        Task<IList<Claim>> GenerateAsync();
    }

    public abstract class ClaimGenerator : IClaimGenerator
    {
        protected readonly IHttpContextAccessor _HttpContextAccessor;

        public ClaimGenerator(IHttpContextAccessor httpContextAccessor)
        {
            _HttpContextAccessor = httpContextAccessor;
        }

        public abstract Task<IList<Claim>> GenerateAsync();
    }
}
