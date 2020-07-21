using OAuth2Net;
using OAuth2Net.Client;
using OAuth2Net.Token;
using System;

namespace Microsoft.Extensions.DependencyInjection
{
    public static class TokenIssuerExtensions
    {
        public static IServiceCollection AddTokenIssuer(this IServiceCollection services, Action<IServiceProvider, TokenIssuerOptions> configOptions)
        {
            services.AddHttpContextAccessor();

            var sp = services.BuildServiceProvider();
            var options = new TokenIssuerOptions();
            configOptions(sp, options);

            services.AddSingleton(options);

            // TokenIssuer
            if (options.TokenIssuer != null)
                // use default
                services.AddSingleton(_ => options.TokenIssuer);
            else
                // use default
                services.AddSingleton<ITokenIssuer, TokenIssuer>();

            // ClientValidator
            if (options.ClientValidator != null)
                services.AddSingleton(_ => options.ClientValidator);
            else
                // use default
                services.AddSingleton<IClientValidator, ClientValidator>();

            // TokenGenerator
            if (options.TokenGenerator != null)
                services.AddSingleton(_ => options.TokenGenerator);
            else
                // use default
                services.AddSingleton<ITokenGenerator, TokenGenerator>();

            // ClaimGenerator
            if (options.ClaimGenerator != null)
                services.AddSingleton(_ => options.ClaimGenerator);
            else
                // no default, must provde
                throw new ArgumentNullException($"options.{nameof(options.ClaimGenerator)}");

            // ClaimGenerator
            if (options.SecurityKeyProvider != null)
                services.AddSingleton(_ => options.SecurityKeyProvider);
            else
                // no default, must provde
                throw new ArgumentNullException($"options.{nameof(options.SecurityKeyProvider)}");

            // ClaimGenerator
            if (options.ClientStore != null)
                services.AddSingleton(_ => options.ClientStore);
            else
                // no default, must provde
                throw new ArgumentNullException($"options.{nameof(options.ClientStore)}");

            return services;
        }
    }
}
