using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using OAuth2NetCore;
using OAuth2NetCore.Redis.State;
using shared;
using SimpleInjector;

namespace client {
    public class Startup {
        static readonly Container _container = ContainerFactory.CreateWithPropertyInjection<ImportPropertySelectionBehavior>();
        public Startup(IConfiguration configuration) {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services) {
            var clientOptions = Configuration.GetSection("OAuth2").Get<ClientOptions>();
            var rediConnStr = Configuration.GetConnectionString("Redis");

            services.AddControllersWithViews();

            // 指定当前项目为支持OAuth2协议的客户端
            services.AddOAuth2Client(o => {
                o.StateStoreFactory = _ => new RedisStateStore(rediConnStr);
                //o.IdentityClaimsBuilder = BuildIdentityClaims;  // 构造登录Cookie Claim，不指定则只有name和role
            }, clientOptions);

            // 整合SimpleInjector
            services.AddSimpleInjector(_container, options => {
                options.AddAspNetCore()
                    .AddControllerActivation();
            });
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env, ClientOptions clientOptions, IClientServer clientServer) {
            app.UseReverseProxy();

            app.UseSimpleInjector(_container);

            if (env.IsDevelopment()) {
                app.UseDeveloperExceptionPage();
            } else {
                app.UseExceptionHandler("/Home/Error");
            }

            app.UseStaticFiles();
            app.UseRouting();
            app.UseAuthentication();
            app.UseAuthorization();

            app.UseEndpoints(endpoints => {
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
