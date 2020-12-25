using IdentityModel.Client;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OAuth;
using Microsoft.IdentityModel.JsonWebTokens;
using OAuth2NetCore;
using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Security.Claims;
using System.Threading.Tasks;

namespace Microsoft.Extensions.DependencyInjection
{
    public static class ClientExtensions
    {
        public static IServiceCollection AddOAuth2Client(this IServiceCollection services, Action<ClientOptions> configOptions)
        {
            var options = new ClientOptions();
            configOptions(options);
            CheckOptions(options);

            services.AddAuthentication(authOptions =>
            {
                authOptions.DefaultAuthenticateScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                authOptions.DefaultSignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                authOptions.DefaultChallengeScheme = OAuthDefaults.DisplayName;
            })
                .AddCookie(cookieOptions =>
                {
                    if (options.AutoRefreshToken)
                    {
                        cookieOptions.Events.OnValidatePrincipal = x => ValidatePrincipal(x, options);
                    }
                })
                .AddOAuth(OAuthDefaults.DisplayName, oauthOptions =>
                {
                    foreach (var scope in options.Scopes)
                    {
                        oauthOptions.Scope.Add(scope);
                    }
                    oauthOptions.ClientId = options.ClientID;
                    oauthOptions.ClientSecret = options.ClientSecret;
                    oauthOptions.AuthorizationEndpoint = options.AuthorizationEndpoint;
                    oauthOptions.TokenEndpoint = options.TokenEndpoint;
                    oauthOptions.CallbackPath = options.CallbackPath;
                    oauthOptions.SaveTokens = options.SaveTokens;
                    oauthOptions.UsePkce = options.UsePkce;

                    oauthOptions.Events.OnCreatingTicket = context =>
                    {
                        var token = new JsonWebToken(context.AccessToken);
                        context.Principal = new ClaimsPrincipal(new ClaimsIdentity(OAuthDefaults.DisplayName, OAuth2Consts.Claim_Name, OAuth2Consts.Claim_Role));

                        var claims = options.IdentityClaimsBuilder(token);
                        foreach (var claim in claims)
                        {
                            context.Identity.AddClaim(claim);
                        }

                        return Task.CompletedTask;
                    };
                });

            return services;
        }

        private static async Task ValidatePrincipal(CookieValidatePrincipalContext context, ClientOptions options)
        {
            var expStr = context.Properties.GetTokenValue(OAuth2Consts.Token_ExpiresAt);
            var now = DateTime.Now;
            var exp = DateTime.Parse(expStr);

            if (now > exp)
            {// expired
                var refreshToken = context.Properties.GetTokenValue(OAuth2Consts.Token_Refresh);
                if (!string.IsNullOrWhiteSpace(refreshToken))
                {// refresh token exists

                    // send refresh token request
                    var refreshTokenResp = await new HttpClient().RequestRefreshTokenAsync(new RefreshTokenRequest
                    {
                        Address = options.TokenEndpoint,
                        ClientId = options.ClientID,
                        ClientSecret = options.ClientSecret,
                        RefreshToken = refreshToken,
                        Scope = string.Join(OAuth2Consts.Seperator_Scope, options.Scopes)
                    });

                    if (!refreshTokenResp.IsError)
                    {// refresh no error
                        context.Properties.UpdateTokenValue(OAuth2Consts.Token_Access, refreshTokenResp.AccessToken);
                        context.Properties.UpdateTokenValue(OAuth2Consts.Token_Refresh, refreshTokenResp.RefreshToken);
                        var expireAt = DateTime.UtcNow.AddSeconds(refreshTokenResp.ExpiresIn).ToString(OAuth2Consts.UtcTimesamp);
                        context.Properties.UpdateTokenValue(OAuth2Consts.Token_ExpiresAt, expireAt);
                        context.ShouldRenew = true;
                        return;
                    }
                }

                // reject principal
                context.RejectPrincipal();
            }
        }

        private static void CheckOptions(ClientOptions options)
        {
            if (options.IdentityClaimsBuilder == null)
            {
                options.IdentityClaimsBuilder = BuildIdentityClaims;
            }

            if (string.IsNullOrWhiteSpace(options.ClientID))
                throw new ArgumentNullException($"{options}.{options.ClientID}");
            if (string.IsNullOrWhiteSpace(options.ClientSecret))
                throw new ArgumentNullException($"{options}.{options.ClientSecret}");
            if (string.IsNullOrWhiteSpace(options.AuthorizationEndpoint))
                throw new ArgumentNullException($"{options}.{options.AuthorizationEndpoint}");
            if (string.IsNullOrWhiteSpace(options.TokenEndpoint))
                throw new ArgumentNullException($"{options}.{options.TokenEndpoint}");
            if (string.IsNullOrWhiteSpace(options.CallbackPath))
                throw new ArgumentNullException($"{options}.{options.CallbackPath}");
        }

        private static IEnumerable<Claim> BuildIdentityClaims(JsonWebToken token)
        {
            foreach (var claim in token.Claims)
            {
                if (claim.Type == OAuth2Consts.Claim_Name || claim.Type == OAuth2Consts.Claim_Role)
                {
                    yield return claim;
                }
            }
        }
    }
}
