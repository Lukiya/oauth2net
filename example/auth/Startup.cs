using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using OAuth2Net;
using OAuth2Net.Client;
using OAuth2Net.Redis.Client;
using OAuth2Net.Security;
using OAuth2Net.Token;

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
            if (HostEnvironment.IsDevelopment())
            {
                mvcBuilder.AddRazorRuntimeCompilation();
            }

            services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
                .AddCookie();

            services.AddTokenIssuer((sp, options) =>
            {
                var contextAccessor = sp.GetService<IHttpContextAccessor>();
                options.ClaimGenerator = new MyClaimGenerator(contextAccessor);
                options.SecurityKeyProvider = new X509FileSecurityKeyProvider("../cert/test.pfx", Configuration.GetValue<string>("CertPass"));
                options.ClientStore = new RedisClientStore(Configuration.GetConnectionString("Redis"), "CLIENTS");
            });
        }

        public void Configure(
              IApplicationBuilder app
            , ITokenIssuer auth2Server
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
                endpoints.MapPost("/connect/token", auth2Server.TokenHandler);

                endpoints.MapControllerRoute(
                    name: "default",
                    pattern: "{controller=Home}/{action=Index}/{id?}");
            });
        }
    }
}
