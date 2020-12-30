using Microsoft.IdentityModel.JsonWebTokens;
using OAuth2NetCore.Store;
using System;
using System.Collections.Generic;
using System.Security.Claims;

namespace OAuth2NetCore
{
    public class ClientOptions
    {
        /// <summary>
        /// Required
        /// </summary>
        public string ClientID { get; set; }
        /// <summary>
        /// Required
        /// </summary>
        public string ClientSecret { get; set; }
        /// <summary>
        /// Required
        /// </summary>
        public string AuthorizationEndpoint { get; set; }
        /// <summary>
        /// Required
        /// </summary>
        public string TokenEndpoint { get; set; }
        /// <summary>
        /// Required
        /// </summary>
        public string EndSessionEndpoint { get; set; }
        /// <summary>
        /// Required (has default)
        /// </summary>
        public string SignInCallbackPath { get; set; } = "/signin-oauth";
        /// <summary>
        /// Required (has default)
        /// </summary>
        public string SignOutPath { get; set; } = "/signout";
        /// <summary>
        /// Required (has default)
        /// </summary>
        public string SignOutCallbackPath { get; set; } = "/signout-oauth";
        /// <summary>
        /// Has default
        /// </summary>
        public bool SaveTokens { get; set; } = true;
        /// <summary>
        /// Has default
        /// </summary>
        public bool UsePkce { get; set; } = true;
        /// <summary>
        /// Has default
        /// </summary>
        public bool AutoRefreshToken { get; set; } = true;
        /// <summary>
        /// Required
        /// </summary>
        public IEnumerable<string> Scopes { get; set; }
        /// <summary>
        /// Required
        /// </summary>
        public IStateStore StateStore { get; set; }
        /// <summary>
        /// Optional
        /// </summary>
        public Func<JsonWebToken, IEnumerable<Claim>> IdentityClaimsBuilder { get; set; }
        /// <summary>
        /// Optional
        /// </summary>
        public IClientServer ClientServer { get; set; }
    }
}
