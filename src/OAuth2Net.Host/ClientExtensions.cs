﻿using IdentityModel.Client;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OAuth;
using Microsoft.IdentityModel.JsonWebTokens;
using OAuth2Net;
using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Security.Claims;
using System.Threading.Tasks;

namespace Microsoft.Extensions.DependencyInjection
{
    public static class ClientExtensions
    {
        public static IServiceCollection AddOAuth2Client(this IServiceCollection services, Action<OAuth2ClientOptions> configOptions)
        {
            var options = new OAuth2ClientOptions();
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

        private static async Task ValidatePrincipal(CookieValidatePrincipalContext context, OAuth2ClientOptions options)
        {
            var expStr = context.Properties.GetTokenValue(OAuth2Consts.Token_ExpiresAt);
            var now = DateTime.Now;
            var exp = DateTime.Parse(expStr);

            if (now > exp)
            {
                var refreshToken = context.Properties.GetTokenValue(OAuth2Consts.Token_Refresh);
                var response = await new HttpClient().RequestRefreshTokenAsync(new RefreshTokenRequest
                {
                    Address = options.TokenEndpoint,
                    ClientId = options.ClientID,
                    ClientSecret = options.ClientSecret,
                    RefreshToken = refreshToken,
                    Scope = string.Join(OAuth2Consts.Seperator_Scope, options.Scopes)
                });

                if (!response.IsError)
                {
                    context.Properties.UpdateTokenValue(OAuth2Consts.Token_Access, response.AccessToken);
                    context.Properties.UpdateTokenValue(OAuth2Consts.Token_Refresh, response.RefreshToken);
                    var expireAt = DateTime.UtcNow.AddSeconds(response.ExpiresIn).ToString(OAuth2Consts.UtcTimesamp);
                    context.Properties.UpdateTokenValue(OAuth2Consts.Token_ExpiresAt, expireAt);
                    context.ShouldRenew = true;
                }
                else
                {
                    // refresh failed
                    context.RejectPrincipal();
                }
            }
        }

        private static void CheckOptions(OAuth2ClientOptions options)
        {
            if (options.IdentityClaimsBuilder == null)
            {
                options.IdentityClaimsBuilder = BuildIdentityClaims;
            }
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
