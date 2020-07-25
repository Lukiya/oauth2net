using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using OAuth2Net;
using OAuth2Net.Redis.Client;
using OAuth2Net.Redis.Token;
using OAuth2Net.Security;
using System.Security.Cryptography.X509Certificates;

namespace auth
{
    public class Startup
    {
        public Startup(IConfiguration configuration, IWebHostEnvironment env)
        {
            Configuration = configuration;
            HostEnvironment = env;
        }

        public IConfiguration Configuration { get; }
        public IWebHostEnvironment HostEnvironment { get; }

        public void ConfigureServices(IServiceCollection services)
        {
            services.Configure<ForwardedHeadersOptions>(options =>
            {
                options.ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto;
            });

            var mvcBuilder = services.AddControllersWithViews();

            services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
                .AddCookie();

            services.AddOAuth2AuthServer((sp, options) =>
            {
                var certPath = "../cert/test.pfx";
                var certPass = Configuration.GetValue<string>("CertPass");
                var cert = new X509Certificate2(certPath, certPass);

                options.ResourceOwnerValidator = new MyResourceOwnerValidator();
                options.ClaimGenerator = new MyClaimGenerator();
                var rediConnStr = Configuration.GetConnectionString("Redis");
                options.SecurityKeyProvider = new X509SecurityKeyProvider(cert);
                options.ClientStore = new RedisClientStore(rediConnStr, "CLIENTS", secretEncryptor: new X509SecretEncryptor(cert));
                options.TokenStore = new RedisTokenStore(rediConnStr, secretEncryptor: new X509SecretEncryptor(cert));
            });
        }

        public void Configure(
              IApplicationBuilder app
            , IAuthServer auth2Server
        )
        {
            app.UseForwardedHeaders();

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

                endpoints.MapControllerRoute(
                    name: "default",
                    pattern: "{controller=Home}/{action=Index}/{id?}");
            });
        }
    }
}