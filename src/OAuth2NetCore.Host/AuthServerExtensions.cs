﻿using OAuth2NetCore;
using OAuth2NetCore.Security;
using OAuth2NetCore.Store;
using OAuth2NetCore.Token;
using System;

namespace Microsoft.Extensions.DependencyInjection
{
    public static class AuthServerExtensions
    {
        public static IServiceCollection AddOAuth2AuthServer(this IServiceCollection services, Action<IServiceProvider, AuthServerOptions> configOptions)
        {
            var sp = services.BuildServiceProvider();
            var options = new AuthServerOptions();
            configOptions(sp, options);

            services.AddSingleton(options);

            CheckOptions(services, options);

            return services;
        }

        private static void CheckOptions(IServiceCollection services, AuthServerOptions options)
        {
            // TokenIssuer
            if (options.AuthServer != null)
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
                throw new ArgumentNullException($"{nameof(options)}.{nameof(options.ResourceOwnerValidator)}");

            // TokenGenerator
            if (options.TokenGenerator != null)
                services.AddSingleton(_ => options.TokenGenerator);
            else
                // use default
                services.AddSingleton<ITokenGenerator, DefaultTokenGenerator>();

            // AuthCodeStore
            if (options.AuthCodeStore != null)
                services.AddSingleton(_ => options.AuthCodeStore);
            else
                // use default
                services.AddSingleton<IAuthCodeStore, DefaultAuthCodeStore>();

            // AuthCodeGenerator
            if (options.AuthCodeGenerator != null)
                services.AddSingleton(_ => options.AuthCodeGenerator);
            else
                // use default
                services.AddSingleton<IAuthCodeGenerator, DefaultAuthCodeGenerator>();

            // PkceValidator
            if (options.PkceValidator != null)
                services.AddSingleton(_ => options.PkceValidator);
            else
                // use default
                services.AddSingleton<IPkceValidator, DefaultPkceValidator>();

            // ClaimGenerator
            if (options.ClaimGenerator != null)
                services.AddSingleton(_ => options.ClaimGenerator);
            else
                // no default, must provde
                throw new ArgumentNullException($"{nameof(options)}.{nameof(options.ClaimGenerator)}");

            // SecurityKeyProvider
            if (options.SecurityKeyProvider != null)
                services.AddSingleton(_ => options.SecurityKeyProvider);
            else
                // no default, must provde
                throw new ArgumentNullException($"{nameof(options)}.{nameof(options.SecurityKeyProvider)}");

            // ClientStore
            if (options.ClientStore != null)
                services.AddSingleton(_ => options.ClientStore);
            else
                // no default, must provde
                throw new ArgumentNullException($"{nameof(options)}.{nameof(options.ClientStore)}");

            // TokenStore
            if (options.TokenStore != null)
                services.AddSingleton(_ => options.TokenStore);
            else
                // no default, must provde
                throw new ArgumentNullException($"{nameof(options)}.{nameof(options.TokenStore)}");
        }
    }
}
