using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using OAuth2Net.Client;
using OAuth2Net.Security;
using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Threading.Tasks;

namespace OAuth2Net.Token
{
    public interface ITokenGenerator
    {
        Task<string> GenerateAsync(GrantType grantType, IClient client, string[] scopes);
    }

    public class TokenGenerator : ITokenGenerator
    {
        private static readonly ClaimCompare _claimCompare = new ClaimCompare();

        public TokenIssuerOptions TokenIssuerOptions { get; }

        private readonly ISecurityKeyProvider _certProvider;
        private readonly IClaimGenerator _claimGenerator;

        public TokenGenerator(ISecurityKeyProvider certProvider, IClaimGenerator claimGenerator, TokenIssuerOptions options)
        {
            TokenIssuerOptions = options;
            _certProvider = certProvider;
            _claimGenerator = claimGenerator;
        }

        public async Task<string> GenerateAsync(GrantType grantType, IClient client, string[] scopes)
        {
            var securityKey = _certProvider.GetSecurityKey();

            var handler = new JsonWebTokenHandler();
            var now = DateTime.UtcNow;

            var claims = await _claimGenerator.GenerateAsync(grantType, client, scopes).ConfigureAwait(false);

            var descriptor = new SecurityTokenDescriptor
            {
                IssuedAt = now,
                NotBefore = now,
                Expires = now.AddSeconds(TokenIssuerOptions.ExpiresInSeconds),
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
