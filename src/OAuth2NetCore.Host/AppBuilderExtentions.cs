using Microsoft.AspNetCore.HttpOverrides;

namespace Microsoft.AspNetCore.Builder
{
    public static class AppBuilderExtentions
    {
        public static IApplicationBuilder UseReverseProxy(this IApplicationBuilder app)
        {
            var options = new ForwardedHeadersOptions
            {
                ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto
            };
            options.KnownNetworks.Clear();
            options.KnownProxies.Clear();
            app.UseForwardedHeaders(options);

            return app;
        }
    }
}
