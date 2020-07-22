using Microsoft.AspNetCore.Http;

namespace OAuth2Net
{
    public interface IAuthServer
    {
        RequestDelegate AuthorizeRequestHandler { get; }
        RequestDelegate TokenRequestHandler { get; }
    }
}
