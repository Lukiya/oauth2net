using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using OAuth2Net;
using OAuth2Net.Client;
using OAuth2Net.Redis.Client;
using OAuth2Net.Secret;

namespace auth
{
    public class Startup
    {
        // This method gets called by the runtime. Use this method to add services to the container.
        // For more information on how to configure your application, visit https://go.microsoft.com/fwlink/?LinkID=398940
        public void ConfigureServices(IServiceCollection services)
        {
            services
                .AddSingleton<IOAuth2Server, OAuth2Server>()
                .AddSingleton<ICertProvider, FileCertProvider>(_ => new FileCertProvider("./public.pem", "./private.key"))
                .AddSingleton<IClientStore, RedisClientStore>(_ => new RedisClientStore("localhost,password=Famous901", "CLIENTS"))
            ;
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
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

            app.UseRouting();

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapPost("/connect/token", auth2Server.TokenHandler);
            });
        }
    }
}
