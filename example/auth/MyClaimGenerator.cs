using Microsoft.AspNetCore.Http;
using OAuth2Net;
using OAuth2Net.Security;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

namespace auth
{
    public class MyClaimGenerator : ClaimGenerator
    {
        public MyClaimGenerator(IHttpContextAccessor httpContextAccessor) : base(httpContextAccessor)
        {
        }

        public override Task<IList<Claim>> GenerateAsync()
        {
            var r = new Claim[] {
                new Claim(Consts.Claim_role, "4"),
            };
            return Task.FromResult<IList<Claim>>(r);
        }
    }
}
