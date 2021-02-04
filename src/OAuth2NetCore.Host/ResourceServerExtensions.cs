using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using System;
using System.IdentityModel.Tokens.Jwt;

namespace Microsoft.Extensions.DependencyInjection
{
    public static class ResourceServerExtensions
    {
        public static IServiceCollection AddOAuth2Resource(this IServiceCollection services, Action<ResourceOptions> configOptions)
        {
            JwtSecurityTokenHandler.DefaultInboundClaimTypeMap.Clear();

            var options = new ResourceOptions();
            configOptions(options);
            CheckOptions(options);

            services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
                .AddJwtBearer(jwtOptions =>
                {
                    jwtOptions.TokenValidationParameters = new TokenValidationParameters
                    {
                        NameClaimType = options.NameClaimType,
                        RoleClaimType = options.RoleClaimType,
                        IssuerSigningKey = options.IssuerSigningKey,
                        ValidIssuer = options.ValidIssuer,
                        ValidAudience = options.ValidAudience,
                    };
                });


            return services;
        }

        private static void CheckOptions(ResourceOptions options)
        {
            if (options.IssuerSigningKey == null)
                throw new ArgumentNullException($"{nameof(options)}.{nameof(options.IssuerSigningKey)}");

            if (string.IsNullOrWhiteSpace(options.ValidAudience))
                throw new ArgumentNullException($"{nameof(options)}.{nameof(options.ValidAudience)}");

            if (string.IsNullOrWhiteSpace(options.ValidIssuer))
                throw new ArgumentNullException($"{nameof(options)}.{nameof(options.ValidIssuer)}");
        }
    }
}
