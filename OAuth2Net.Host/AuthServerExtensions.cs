using OAuth2Net;
using OAuth2Net.Client;
using OAuth2Net.Security;
using OAuth2Net.Token;
using System;

namespace Microsoft.Extensions.DependencyInjection
{
    public static class AuthServerExtensions
    {
        public static IServiceCollection AddAuthServer(this IServiceCollection services, Action<IServiceProvider, AuthServerOptions> configOptions)
        {
            var sp = services.BuildServiceProvider();
            var options = new AuthServerOptions();
            configOptions(sp, options);

            if (options.ExpiresInSeconds <= 0)
            {
                throw new ArgumentOutOfRangeException(nameof(options.ExpiresInSeconds), "ExpiresInSeconds must be positive integer");
            }

            services.AddSingleton(options);

            // TokenIssuer
            if (options.AuthServer != null)
                // use default
                services.AddSingleton(_ => options.AuthServer);
            else
                // use default
                services.AddSingleton<IAuthServer, DefaultAuthServer>();

            // ClientValidator
            if (options.ClientValidator != null)
                services.AddSingleton(_ => options.ClientValidator);
            else
                // use default
                services.AddSingleton<IClientValidator, DefaultClientValidator>();

            // ResourceOwnerValidator
            if (options.ResourceOwnerValidator != null)
                services.AddSingleton(_ => options.ResourceOwnerValidator);
            else
                // use default
                services.AddSingleton<IResourceOwnerValidator, NotSupportResourceOwnerValidator>();

            // TokenGenerator
            if (options.TokenGenerator != null)
                services.AddSingleton(_ => options.TokenGenerator);
            else
                // use default
                services.AddSingleton<ITokenGenerator, DefaultTokenGenerator>();

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
