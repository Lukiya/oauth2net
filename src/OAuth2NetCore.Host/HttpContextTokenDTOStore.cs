﻿using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.JsonWebTokens;
using OAuth2NetCore.Model;
using OAuth2NetCore.Store;
using System;
using System.Text.Json;
using System.Threading.Tasks;

namespace OAuth2NetCore.Host
{
    internal class HttpContextTokenDTOStore : ITokenDTOStore
    {
        private readonly ILogger<HttpContextTokenDTOStore> _logger;
        private readonly IHttpContextAccessor _httpContextAccessor;
        private readonly ISecureDataFormat<TokenDTO> _tokenDTOProector;
        private const string _authCookieName = "auth.cookie2";

        public HttpContextTokenDTOStore(IHttpContextAccessor httpContextAccessor, ISecureDataFormat<TokenDTO> tokenDTOProector, ILogger<HttpContextTokenDTOStore> logger)
        {
            _logger = logger;
            _httpContextAccessor = httpContextAccessor;
            _tokenDTOProector = tokenDTOProector;
        }

        public Task<JsonWebToken> SaveTokenDTOAsync(string json)
        {
            if (_httpContextAccessor.HttpContext != null)
            {
                //var json = jsonDoc.ToJsonString();
                var tokenDTO = JsonSerializer.Deserialize<TokenDTO>(json);

                var cookieOptions = new CookieOptions();

                var jwt = new JsonWebToken(tokenDTO.AccessToken);
                if (jwt.TryGetPayloadValue<long>(OAuth2Consts.Claim_RefreshTokenExpire, out var rexp))
                {
                    cookieOptions.Expires = DateTimeOffset.FromUnixTimeSeconds(rexp);
                }

                _httpContextAccessor.HttpContext.Response.Cookies.Append(_authCookieName, _tokenDTOProector.Protect(tokenDTO), cookieOptions);
                return Task.FromResult<JsonWebToken>(jwt);
            }
            else
            {
                _logger.LogWarning($"{nameof(_httpContextAccessor)}.{_httpContextAccessor.HttpContext} is null");
                return Task.FromResult<JsonWebToken>(null);
            }
        }

        public Task<TokenDTO> GetTokenDTOAsync()
        {
            if (_httpContextAccessor.HttpContext != null)
            {
                var protectedText = _httpContextAccessor.HttpContext.Request.Cookies[_authCookieName];
                if (string.IsNullOrWhiteSpace(protectedText))
                    return null;

                var tokenDTO = _tokenDTOProector.Unprotect(protectedText);

                return Task.FromResult(tokenDTO);
            }

            _logger.LogWarning($"{nameof(_httpContextAccessor)}.{_httpContextAccessor.HttpContext} is null");
            return Task.FromResult<TokenDTO>(null);
        }
    }
}
