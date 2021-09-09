using auth2net;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using NUnit.Framework;
using OAuth2NetCore.Redis.Client;
using OAuth2NetCore.Redis.State;
using OAuth2NetCore.Redis.Token;
using OAuth2NetCore.Security;
using System;
using System.IO;
using System.Security.Cryptography.X509Certificates;

[SetUpFixture]
public class Engine {
    public static IServiceProvider ServiceProvider { get; private set; }

    static IConfiguration Configuration = new ConfigurationBuilder()
                        .SetBasePath(Directory.GetCurrentDirectory())
                        .AddJsonFile("appsettings.json", optional: false, reloadOnChange: true)
                        .Build();


    [OneTimeSetUp]
    public static void Init() {
        var services = new ServiceCollection()
            .AddOAuth2AuthServer(options => {
                var rediConnStr = Configuration.GetConnectionString("REDIS_DEFAULT");
                var certPath = Configuration.GetValue<string>("ECP:CertPath");
                var certPass = Configuration.GetValue<string>("ECP:CertPass");
                var mainCert = new X509Certificate2(certPath, certPass);

                options.RefreshTokenInfoStore = _ => new RedisRefreshTokenInfoStore(rediConnStr, secretEncryptor: new X509SecretEncryptor(mainCert));
                options.SecurityKeyProviderFactory = _ => new X509SecurityKeyProvider(mainCert);
                options.StateStoreFactory = _ => new RedisStateStore(
                    rediConnStr
                    , prefix: "ecst:"
                );
                options.ClientStoreFactory = _ => new RedisClientStore(
                    rediConnStr
                    , "ec:CLIENTS"
                    , secretEncryptor: new X509SecretEncryptor(mainCert)
                );

                options.TokenClaimBuilderFactory = _ => null;
                options.ResourceOwnerValidatorFactory = _ => null;

                options.WellknownFactory = _ => new TestWellknown(new X509JsonWebKeyProvider(mainCert));
            })
            .AddLogging(logBuilder => {
                logBuilder.SetMinimumLevel(LogLevel.Debug);
                logBuilder.AddConsole();
            })
            ;

        ServiceProvider = services.BuildServiceProvider();
    }
}
