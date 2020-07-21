namespace OAuth2Net
{
    public static class OAuth2Consts
    {
        public const string Header_Authorization = "Authorization";
        public const string Claim_Role = "role";
        public const string Claim_Name = "name";
        public const string Claim_Audience = "aud";
        public const string Claim_Issuer = "iss";
        public const string Form_GrantType = "grant_type";
        public const string Form_Scope = "scope";
        public const string GrantType_Client = "client_credentials";
        public const string GrantType_Code = "code";
        public const string GrantType_Implicit = "token";
        public const string GrantType_Owner = "password";
        public const string Tmpl_Token1 = "{{\"access_token\":\"{0}\",\"expires_in\":\"{1}\",\"scope\":\"{2}\",\"token_type\":\"Bearer\"}}";
        public const string Tmpl_Token2 = "{{\"access_token\":\"{0}\",\"refresh_token\":\"{1}\",\"expires_in\":\"{2}\",\"scope\":\"{3}\",\"token_type\":\"Bearer\"}}";
        public const string Msg_Success = "";
    }
}