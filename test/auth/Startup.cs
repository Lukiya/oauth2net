using auth.Services;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using OAuth2NetCore;
using OAuth2NetCore.Redis.Client;
using OAuth2NetCore.Redis.Token;
using OAuth2NetCore.Security;
using OAuth2NetCore.Store;
using OAuth2NetCore.Token;
using shared;
using SimpleInjector;
using System.Security.Cryptography.X509Certificates;

namespace auth
{
    public class Startup
    {
        static readonly Container _container = ContainerFactory.CreateWithPropertyInjection<ImportPropertySelectionBehavior>();
        public Startup(IConfiguration configuration, IWebHostEnvironment env)
        {
            Configuration = configuration;
            HostEnvironment = env;
        }

        public IConfiguration Configuration { get; }
        public IWebHostEnvironment HostEnvironment { get; }

        public void ConfigureServices(IServiceCollection services)
        {
            var rediConnStr = Configuration.GetConnectionString("Redis");
            var certPath = Configuration.GetValue<string>("CertPath");
            var certPass = Configuration.GetValue<string>("CertPass");

            services.AddControllersWithViews();

            services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
                .AddCookie();


            var cert = new X509Certificate2(certPath, certPass);
            services.AddSingleton<IClientStore>(sp => new RedisClientStore(rediConnStr, "test:Clients", secretEncryptor: new X509SecretEncryptor(cert)));
            services.AddSingleton<ITokenStore>(sp => new RedisTokenStore(rediConnStr, secretEncryptor: new X509SecretEncryptor(cert)));
            services.AddSingleton<ISecurityKeyProvider>(sp => new X509SecurityKeyProvider(cert));
            services.AddSingleton<IResourceOwnerValidator, MyResourceOwnerValidator>();
            services.AddSingleton<ITokenClaimGenerator, MyTokenClaimGenerator>();

            services.AddOAuth2AuthServer((sp, options) =>
            {
                options.ResourceOwnerValidator = sp.GetService<IResourceOwnerValidator>();
                options.ClaimGenerator = sp.GetService<ITokenClaimGenerator>();
                options.SecurityKeyProvider = sp.GetService<ISecurityKeyProvider>();
                options.ClientStore = sp.GetService<IClientStore>();
                options.TokenStore = sp.GetService<ITokenStore>();
            });

            services.AddSimpleInjector(_container, options =>
            {
                options.AddAspNetCore()
                    .AddControllerActivation();

                options.AddLogging();
            });

            services.AddLazySingleton<IUserService, UserService>();
        }


        public void Configure(
              IApplicationBuilder app
            , IAuthServer auth2Server
        )
        {
            app.UseReverseProxy();

            app.UseSimpleInjector(_container);

            if (HostEnvironment.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }
            else
            {
                app.UseExceptionHandler("/Home/Error");
            }
            app.UseStaticFiles();

            app.UseRouting();

            app.UseAuthentication();
            app.UseAuthorization();

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapPost("/connect/token", auth2Server.TokenRequestHandler);
                endpoints.MapGet("/connect/authorize", auth2Server.AuthorizeRequestHandler);
                endpoints.MapGet("/connect/endsession", auth2Server.EndSessionRequestHandler);

                endpoints.MapControllerRoute(
                    name: "default",
                    pattern: "{controller=Home}/{action=Index}/{id?}");
            });

            _container.Verify();
        }
    }
}
