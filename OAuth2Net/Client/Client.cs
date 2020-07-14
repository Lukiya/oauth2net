using System;
using System.Collections.Generic;

namespace OAuth2Net.Client
{
    public interface IClient
    {
        string ID { get; set; }
        string Secert { get; set; }
        IList<string> GrantTypes { get; set; }
        IList<string> Scopes { get; set; }
        IList<string> RedirectUris { get; set; }
    }

    public class Client : IClient
    {
        public string ID { get; set; }
        public string Secert { get; set; }
        public IList<string> GrantTypes { get; set; }
        public IList<string> Scopes { get; set; }
        public IList<string> RedirectUris { get; set; }
    }
}
