using System.Collections.Generic;

namespace OAuth2Net.Model
{
    public interface IClient
    {
        string ID { get; set; }
        string Secret { get; set; }
        IList<string> Grants { get; set; }
        IList<string> Scopes { get; set; }
        IList<string> RedirectUris { get; set; }
    }

    public class Client : IClient
    {
        public string ID { get; set; }
        public string Secret { get; set; }
        public IList<string> Grants { get; set; }
        public IList<string> Scopes { get; set; }
        public IList<string> RedirectUris { get; set; }
    }
}
