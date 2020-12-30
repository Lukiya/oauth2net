using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using OAuth2NetCore;
using OAuth2NetCore.Redis.State;
using shared;
using SimpleInjector;
using System.Collections.Concurrent;

namespace client
{
    public class Startup
    {
        static readonly Container _container = ContainerFactory.CreateWithPropertyInjection<ImportPropertySelectionBehavior>();
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            var clientOptions = Configuration.GetSection("OAuth2").Get<ClientOptions>();
            var rediConnStr = Configuration.GetConnectionString("Redis");

            services.AddControllersWithViews();

            services.AddOAuth2Client(clientOptions, o =>
            {
                o.StateStoreFactory = _ => new RedisStateStore(rediConnStr);
            });

            services.AddSimpleInjector(_container, options =>
            {
                options.AddAspNetCore()
                    .AddControllerActivation();
            });
        }

        private static readonly ConcurrentDictionary<string, string> _states = new ConcurrentDictionary<string, string>();

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env, ClientOptions clientOptions, IClientServer clientServer)
        {
            app.UseReverseProxy();

            app.UseSimpleInjector(_container);

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

            app.UseAuthentication();
            app.UseAuthorization();

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapGet(clientOptions.SignOutPath, clientServer.SignOutRequestHandler);
                endpoints.MapGet(clientOptions.SignOutCallbackPath, clientServer.SignOutCallbackRequestHandler);

                endpoints.MapControllerRoute(
                    name: "default",
                    pattern: "{controller=Home}/{action=Index}/{id?}");
            });

            _container.Verify();
        }
    }
}
