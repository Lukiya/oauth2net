using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OAuth;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using System;
using System.Threading.Tasks;

namespace client
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            services.Configure<ForwardedHeadersOptions>(options =>
            {
                options.ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto;
            });

            services.AddControllersWithViews();

            services.AddAuthentication(options =>
            {
                options.DefaultAuthenticateScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                options.DefaultSignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                options.DefaultChallengeScheme = OAuthDefaults.DisplayName;
            })
                .AddCookie()
                .AddOAuth(OAuthDefaults.DisplayName, options =>
                {
                    var scopesSection = Configuration.GetSection("OAuth:Scopes").GetChildren();
                    foreach (var scope in scopesSection)
                    {
                        options.Scope.Add(scope.Value);
                    }

                    options.ClientId = Configuration.GetValue<string>("OAuth:ClientID");
                    options.ClientSecret = Configuration.GetValue<string>("OAuth:ClientSecret");
                    options.AuthorizationEndpoint = Configuration.GetValue<string>("OAuth:AuthorizationEndpoint");
                    options.TokenEndpoint = Configuration.GetValue<string>("OAuth:TokenEndpoint");
                    options.CallbackPath = "/signin-oauth";

                    //options.SaveTokens = true;
                    // 事件执行顺序 ：
                    // 1.创建Ticket之前触发
                    options.Events.OnCreatingTicket = context =>
                    {
                        Console.WriteLine("on creating ticket");
                        return Task.CompletedTask;
                    };
                    // 2.创建Ticket失败时触发
                    options.Events.OnRemoteFailure = context =>
                    {
                        Console.WriteLine("on remote failure");
                        return Task.CompletedTask;
                    };
                    // 3.Ticket接收完成之后触发
                    options.Events.OnTicketReceived = context =>
                    {
                        Console.WriteLine("on ticket received");
                        return Task.CompletedTask;
                    };
                    // 4.Challenge时触发，默认跳转到OAuth服务器
                    // options.Events.OnRedirectToAuthorizationEndpoint = context => context.Response.Redirect(context.RedirectUri);
                });
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            app.UseForwardedHeaders();

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
                endpoints.MapControllerRoute(
                    name: "default",
                    pattern: "{controller=Home}/{action=Index}/{id?}");
            });
        }
    }
}
