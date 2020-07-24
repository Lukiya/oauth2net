using System.Collections.Generic;

namespace OAuth2Net.Model
{
    public class Client : IClient
    {
        public string ID { get; set; }
        public string Secret { get; set; }
        public IList<string> Grants { get; set; }
        public IList<string> Scopes { get; set; }
        public IList<string> RedirectUris { get; set; }
    }

}
