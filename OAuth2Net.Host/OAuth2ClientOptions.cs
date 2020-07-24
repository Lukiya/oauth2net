using System.Collections.Generic;

namespace Microsoft.Extensions.DependencyInjection
{
    public class OAuth2ClientOptions
    {
        public string ClientID { get; set; }
        public string ClientSecret { get; set; }
        public string AuthorizationEndpoint { get; set; }
        public string TokenEndpoint { get; set; }
        public string CallbackPath { get; set; }
        public IEnumerable<string> Scopes { get; set; }
    }
}
