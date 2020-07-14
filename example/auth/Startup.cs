using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Newtonsoft.Json;
using OAuth2Net.Client;
using OAuth2Net.Redis.Client;

namespace auth
{
    public class Startup
    {
        // This method gets called by the runtime. Use this method to add services to the container.
        // For more information on how to configure your application, visit https://go.microsoft.com/fwlink/?LinkID=398940
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddSingleton<IClientStore, RedisClientStore>(_ => new RedisClientStore("localhost,password=Famous901", "CLIENTS"));
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env, IClientStore clientStore)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }

            app.UseRouting();

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapPost("/connect/token", async context =>
                {
                    var client = await clientStore.GetClientAsync("armos").ConfigureAwait(false);
                    var clients = await clientStore.GetClientsAsync().ConfigureAwait(false);
                    var json = JsonConvert.SerializeObject(clients);
                    await context.Response.WriteAsync(json);
                });
            });
        }
    }
}
