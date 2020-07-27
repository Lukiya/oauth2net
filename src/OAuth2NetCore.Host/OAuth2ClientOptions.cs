using Microsoft.IdentityModel.JsonWebTokens;
using System;
using System.Collections.Generic;
using System.Security.Claims;

namespace Microsoft.Extensions.DependencyInjection
{
    public class OAuth2ClientOptions
    {
        public string ClientID { get; set; }
        public string ClientSecret { get; set; }
        public string AuthorizationEndpoint { get; set; }
        public string TokenEndpoint { get; set; }
        public string CallbackPath { get; set; }
        public IEnumerable<string> Scopes { get; set; }
        public bool SaveTokens { get; set; } = true;
        public bool UsePkce { get; set; } = true;
        public bool AutoRefreshToken { get; set; } = true;
        public Func<JsonWebToken, IEnumerable<Claim>> IdentityClaimsBuilder { get; set; }
    }
}
