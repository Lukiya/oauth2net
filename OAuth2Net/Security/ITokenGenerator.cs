using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace OAuth2Net.Security
{
    public interface ITokenGenerator
    {
        Task<string> GenerateAsync(int expireSeconds, params Claim[] builtInClaims);
    }

    public class TokenGenerator : ITokenGenerator
    {
        private static readonly ClaimCompare _claimCompare = new ClaimCompare();
        private readonly ICertProvider _certProvider;
        private readonly IClaimGenerator _claimGenerator;

        public TokenGenerator(ICertProvider certProvider, IClaimGenerator claimGenerator)
        {
            _certProvider = certProvider;
            _claimGenerator = claimGenerator;
        }

        public async Task<string> GenerateAsync(int expireSeconds, params Claim[] builtInClaims)
        {
            var securityKey = _certProvider.GetSecurityKey();

            var handler = new JsonWebTokenHandler();
            var now = DateTime.UtcNow;

            var claims = await _claimGenerator.GenerateAsync().ConfigureAwait(false);
            if (builtInClaims.Length > 0)
            {
                claims = claims.Union(builtInClaims, _claimCompare).ToList();
            }

            var descriptor = new SecurityTokenDescriptor
            {
                Issuer = "http://localhost:5000",
                Audience = "report",
                IssuedAt = now,
                NotBefore = now,
                Expires = now.AddSeconds(expireSeconds),
                Subject = new ClaimsIdentity(claims),
                SigningCredentials = new SigningCredentials(securityKey, SecurityAlgorithms.RsaSsaPssSha256)
            };

            string token = handler.CreateToken(descriptor);
            return token;
        }
    }

    public class ClaimCompare : IEqualityComparer<Claim>
    {
        public bool Equals(Claim x, Claim y) => x.Type == y.Type;

        public int GetHashCode(Claim obj) => obj.GetHashCode();
    }
}
