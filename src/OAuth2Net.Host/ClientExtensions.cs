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
                    cookieOptions.Events.OnValidatePrincipal = x => ValidatePrincipal(x, options);
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
            // since our cookie lifetime is based on the access token one,
            // check if we're more than halfway of the cookie lifetime
            //var now = DateTimeOffset.UtcNow;
            //var timeElapsed = now.Subtract(context.Properties.IssuedUtc.Value);
            //var timeRemaining = context.Properties.ExpiresUtc.Value.Subtract(now);
            var expStr = context.Properties.GetTokenValue("expires_at");
            var now = DateTime.Now;
            var exp = DateTime.Parse(expStr);

            if (now > exp)
            {
                //var identity = (ClaimsIdentity)context.Principal.Identity;
                //var accessTokenClaim = identity.FindFirst("access_token");
                //var refreshTokenClaim = identity.FindFirst("refresh_token");

                // if we have to refresh, grab the refresh token from the claims, and request
                // new access token and refresh token
                var refreshToken = context.Properties.GetTokenValue(OAuth2Consts.Form_RefreshToken);
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
                    //// everything went right, remove old tokens and add new ones
                    //identity.RemoveClaim(accessTokenClaim);
                    //identity.RemoveClaim(refreshTokenClaim);

                    //identity.AddClaims(new[]
                    //{
                    //                new Claim("access_token", response.AccessToken),
                    //                new Claim("refresh_token", response.RefreshToken)
                    //            });

                    // indicate to the cookie middleware to renew the session cookie
                    // the new lifetime will be the same as the old one, so the alignment
                    // between cookie and access token is preserved

                    context.Properties.UpdateTokenValue(OAuth2Consts.Form_AccessToken, response.AccessToken);
                    context.Properties.UpdateTokenValue(OAuth2Consts.Form_RefreshToken, response.RefreshToken);
                    //context.Properties.UpdateTokenValue(OAuth2Consts.Form_RefreshToken, response.ExpiresIn);

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
