using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using NUnit.Framework;
using OAuth2NetCore;
using System.Threading.Tasks;

namespace oauth2net {
    public class AuthServer {
        private readonly IAuthServer _authServer;

        public AuthServer() {
            _authServer = Engine.ServiceProvider.GetService<IAuthServer>();
        }

        [Test]
        public async Task OpenIDConfigRequest() {
            var httpContext = new DefaultHttpContext();
            await _authServer.OpenIDConfigRequestHandler(httpContext);
        }

        [Test]
        public async Task OpenIDJwksRequest() {
            var httpContext = new DefaultHttpContext();
            await _authServer.OpenIDJwksRequestHandler(httpContext);
        }
    }
}