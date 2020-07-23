namespace OAuth2Net.Model
{
    public class TokenRequestInfo
    {
        public string ClientID { get; set; }
        public string Scopes { get; set; }
        public string RedirectUri { get; set; }
        public string Username { get; set; }
    }
}
