using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using OAuth2Net;
using OAuth2Net.Client;
using OAuth2Net.Redis.Client;
using OAuth2Net.Security;

namespace auth
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        public void ConfigureServices(IServiceCollection services)
        {
            services.AddControllersWithViews();

            services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
                .AddCookie();

            services
                .AddHttpContextAccessor()
                .AddSingleton<IOAuth2Server, OAuth2Server>()
                .AddSingleton<IClientValidator, ClientValidator>()
                .AddSingleton<ITokenGenerator, TokenGenerator>()
                .AddSingleton<IClaimGenerator, MyClaimGenerator>()
                .AddSingleton<ICertProvider, FileCertProvider>(_ => new FileCertProvider("../cert/test.pfx", Configuration.GetValue<string>("CertPass")))
                .AddSingleton<IClientStore, RedisClientStore>(_ => new RedisClientStore(Configuration.GetConnectionString("Redis"), "CLIENTS"))
            ;
        }

        public void Configure(
              IApplicationBuilder app
            , IWebHostEnvironment env
            , IOAuth2Server auth2Server
        )
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }
            else
            {
                app.UseExceptionHandler("/Home/Error");
            }
            app.UseStaticFiles();

            app.UseRouting();

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
