using IdentityModel.Client;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OAuth;
using Microsoft.IdentityModel.JsonWebTokens;
using OAuth2Net;
using System;
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

            services.AddAuthentication(authOptions =>
            {
                authOptions.DefaultAuthenticateScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                authOptions.DefaultSignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                authOptions.DefaultChallengeScheme = OAuthDefaults.DisplayName;
            })
                .AddCookie(cookieOptions =>
                {
                    cookieOptions.Events.OnValidatePrincipal = async x =>
                    {
                        // since our cookie lifetime is based on the access token one,
                        // check if we're more than halfway of the cookie lifetime
                        var now = DateTimeOffset.UtcNow;
                        var timeElapsed = now.Subtract(x.Properties.IssuedUtc.Value);
                        var timeRemaining = x.Properties.ExpiresUtc.Value.Subtract(now);

                        if (timeElapsed > timeRemaining)
                        {
                            var identity = (ClaimsIdentity)x.Principal.Identity;
                            var accessTokenClaim = identity.FindFirst("access_token");
                            var refreshTokenClaim = identity.FindFirst("refresh_token");

                            // if we have to refresh, grab the refresh token from the claims, and request
                            // new access token and refresh token
                            var refreshToken = refreshTokenClaim.Value;
                            var response = await new HttpClient().RequestRefreshTokenAsync(new RefreshTokenRequest
                            {
                                Address = options.TokenEndpoint,
                                ClientId = options.ClientID,
                                ClientSecret = options.ClientSecret,
                                RefreshToken = refreshToken
                            });

                            if (!response.IsError)
                            {
                                // everything went right, remove old tokens and add new ones
                                identity.RemoveClaim(accessTokenClaim);
                                identity.RemoveClaim(refreshTokenClaim);

                                identity.AddClaims(new[]
                                {
                                    new Claim("access_token", response.AccessToken),
                                    new Claim("refresh_token", response.RefreshToken)
                                });

                                // indicate to the cookie middleware to renew the session cookie
                                // the new lifetime will be the same as the old one, so the alignment
                                // between cookie and access token is preserved
                                x.ShouldRenew = true;
                            }
                            else
                            {
                                // refresh failed
                                x.RejectPrincipal();
                            }
                        }
                    };
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
                    oauthOptions.SaveTokens = true;
                    //options.UsePkce = configuration.GetValue<bool>("OAuth:UsePkce");

                    oauthOptions.Events.OnCreatingTicket = context =>
                    {
                        var token = new JsonWebToken(context.AccessToken);
                        context.Principal = new ClaimsPrincipal(new ClaimsIdentity(OAuthDefaults.DisplayName, OAuth2Consts.Claim_Name, OAuth2Consts.Claim_Role));

                        if (token.TryGetClaim(OAuth2Consts.Claim_Name, out var nameClaim))
                        {
                            context.Identity.AddClaim(nameClaim);
                        }
                        if (token.TryGetClaim(OAuth2Consts.Claim_Role, out var roleClaim))
                        {
                            context.Identity.AddClaim(roleClaim);
                        }

                        return Task.CompletedTask;
                    };
                });

            return services;
        }
    }
}
