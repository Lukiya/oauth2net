﻿using Microsoft.AspNetCore.Http;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using OAuth2Net.Model;
using OAuth2Net.Security;
using System;
using System.Security.Claims;
using System.Threading.Tasks;

namespace OAuth2Net.Token
{
    public class DefaultTokenGenerator : ITokenGenerator
    {
        public AuthServerOptions AuthServerOptions { get; }

        private readonly ISecurityKeyProvider _securityKeyProvider;
        private readonly ITokenClaimGenerator _claimGenerator;

        public DefaultTokenGenerator(ISecurityKeyProvider certProvider, ITokenClaimGenerator claimGenerator, AuthServerOptions options)
        {
            AuthServerOptions = options;
            _securityKeyProvider = certProvider;
            _claimGenerator = claimGenerator;
        }

        public async Task<string> GenerateAccessTokenAsync(HttpContext context, GrantType grantType, IClient client, string[] scopes, string username)
        {
            var securityKey = _securityKeyProvider.GetSecurityKey();

            var handler = new JsonWebTokenHandler();
            var now = DateTime.UtcNow;

            var claims = await _claimGenerator.GenerateAsync(context, grantType, client, scopes, username).ConfigureAwait(false);

            var descriptor = new SecurityTokenDescriptor
            {
                IssuedAt = now,
                NotBefore = now,
                Expires = now.AddSeconds(AuthServerOptions.ExpiresInSeconds),
                Subject = new ClaimsIdentity(claims),
                SigningCredentials = new SigningCredentials(securityKey, AuthServerOptions.SigningAlgorithm)
            };

            string token = handler.CreateToken(descriptor);
            return token;
        }

        public Task<string> GenerateRefreshTokenAsync()
        {
            return Task.FromResult(Guid.NewGuid().ToString("N") + Guid.NewGuid().ToString("N"));
        }
    }
}