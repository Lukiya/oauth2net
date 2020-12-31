using IdentityModel.Client;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OAuth;
using Microsoft.IdentityModel.JsonWebTokens;
using OAuth2NetCore;
using OAuth2NetCore.Security;
using System;
using System.Net.Http;
using System.Security.Claims;
using System.Threading.Tasks;
using ClientOptions = OAuth2NetCore.ClientOptions;

namespace Microsoft.Extensions.DependencyInjection
{
    public static class ClientExtensions
    {
        private static readonly HttpClient _httpClient = new HttpClient();  // This won't honor DNS changes. TODO: use IHttpClientFactory.CreateClient
        public static IServiceCollection AddOAuth2Client(this IServiceCollection services, ClientOptions options, Action<ClientOptions> configOptions)
        {
            configOptions(options);
            CheckOptions(services, options);

            services.AddSingleton(options);

            services.AddAuthentication(authOptions =>
            {
                authOptions.DefaultAuthenticateScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                authOptions.DefaultSignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                authOptions.DefaultChallengeScheme = OAuthDefaults.DisplayName;
            })
                .AddCookie(o =>
                {
                    //o.Events.OnSigningIn = context =>
                    //{
                    //    //context.Properties.IsPersistent = true;
                    //    //context.Properties.ExpiresUtc = DateTimeOffset.UtcNow.AddDays(14);
                    //    var expStr = context.Properties.GetTokenValue(OAuth2Consts.Form_RefreshToken);
                    //    return Task.CompletedTask;
                    //};
                    if (options.AutoRefreshToken)
                    {
                        o.Events.OnValidatePrincipal = x => ValidatePrincipal(x, options);
                    }
                })
                .AddOAuth(OAuthDefaults.DisplayName, o =>
                {
                    foreach (var scope in options.Scopes)
                    {
                        o.Scope.Add(scope);
                    }
                    o.ClientId = options.ClientID;
                    o.ClientSecret = options.ClientSecret;
                    o.AuthorizationEndpoint = options.AuthorizationEndpoint;
                    o.TokenEndpoint = options.TokenEndpoint;
                    o.CallbackPath = options.SignInCallbackPath;
                    o.SaveTokens = options.SaveTokens;
                    o.UsePkce = options.UsePkce;

                    o.Events.OnCreatingTicket = context =>
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
            if (!DateTimeOffset.TryParse(expStr, out var exp))
            {// expStr format invalid
                // reject principal
                context.RejectPrincipal();
                // sign user out
                await context.HttpContext.SignOutAsync().ConfigureAwait(false);
                return;
            }

            if (DateTimeOffset.UtcNow > exp)
            {// access token expired
                var refreshToken = context.Properties.GetTokenValue(OAuth2Consts.Token_Refresh);
                if (!string.IsNullOrWhiteSpace(refreshToken))
                {// refresh token exists

                    // send refresh token request
                    var refreshTokenResp = await _httpClient.RequestRefreshTokenAsync(new RefreshTokenRequest
                    {
                        Address = options.TokenEndpoint,
                        ClientId = options.ClientID,
                        ClientSecret = options.ClientSecret,
                        RefreshToken = refreshToken,
                        Scope = string.Join(OAuth2Consts.Seperator_Scope, options.Scopes)
                    });

                    if (!refreshTokenResp.IsError)
                    {// refresh success
                        context.Properties.UpdateTokenValue(OAuth2Consts.Token_Access, refreshTokenResp.AccessToken);
                        context.Properties.UpdateTokenValue(OAuth2Consts.Token_Refresh, refreshTokenResp.RefreshToken);
                        var expireAt = DateTimeOffset.UtcNow.AddSeconds(refreshTokenResp.ExpiresIn).ToString(OAuth2Consts.UtcTimesamp);
                        context.Properties.UpdateTokenValue(OAuth2Consts.Token_ExpiresAt, expireAt);
                        context.ShouldRenew = true;
                        return;
                    }
                }

                // reject principal
                context.RejectPrincipal();
                // sign user out
                await context.HttpContext.SignOutAsync().ConfigureAwait(false);
            }
        }

        private static void CheckOptions(IServiceCollection services, ClientOptions options)
        {
            if (options.IdentityClaimsBuilder == null)
                throw new ArgumentNullException($"{nameof(options)}.{nameof(options.IdentityClaimsBuilder)}");
            if (string.IsNullOrWhiteSpace(options.ClientID))
                throw new ArgumentNullException($"{nameof(options)}.{nameof(options.ClientID)}");
            if (string.IsNullOrWhiteSpace(options.ClientSecret))
                throw new ArgumentNullException($"{nameof(options)}.{nameof(options.ClientSecret)}");
            if (string.IsNullOrWhiteSpace(options.AuthorizationEndpoint))
                throw new ArgumentNullException($"{nameof(options)}.{nameof(options.AuthorizationEndpoint)}");
            if (string.IsNullOrWhiteSpace(options.TokenEndpoint))
                throw new ArgumentNullException($"{nameof(options)}.{nameof(options.TokenEndpoint)}");
            if (string.IsNullOrWhiteSpace(options.SignInCallbackPath))
                throw new ArgumentNullException($"{nameof(options)}.{nameof(options.SignInCallbackPath)}");
            if (string.IsNullOrWhiteSpace(options.SignOutCallbackPath))
                throw new ArgumentNullException($"{nameof(options)}.{nameof(options.SignOutCallbackPath)}");
            if (string.IsNullOrWhiteSpace(options.SignOutPath))
                throw new ArgumentNullException($"{nameof(options)}.{nameof(options.SignOutPath)}");

            // StateStore
            if (options.StateStoreFactory != null)
                services.AddSingleton(options.StateStoreFactory);
            else
                throw new ArgumentNullException($"{nameof(options)}.{nameof(options.StateStoreFactory)}");

            if (options.StateGeneratorFactory != null)
                services.AddSingleton(options.StateGeneratorFactory);
            else
                // use default
                services.AddSingleton<IStateGenerator, DefaultStateGenerator>();

            if (options.ClientServerFactory != null)
                services.AddSingleton(options.ClientServerFactory);
            else
                // use default
                services.AddSingleton<IClientServer, DefaultClientServer>();
        }
    }
}
