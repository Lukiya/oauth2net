using OAuth2Net.Client;
using OAuth2Net.Security;
using OAuth2Net.Token;
using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace OAuth2Net
{
    public static class Consts
    {
        public const string Header_Authorization = "Authorization";
        //public const string Claim_nbf = "nbf";
        //public const string Claim_exp = "exp";
        //public const string Claim_typ = "typ";
        //public const string Claim_typ_JWT = "JWT";
        //public const string Claim_alg = "alg";
        //public const string Claim_alg_RS256 = "RS256";
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

    public class MessageResult<T>
    {
        public string Message { get; set; } = Consts.Msg_Success;
        public T Result { get; set; }

        public bool IsSuccess => Message == Consts.Msg_Success;
    }

    public static class Base64Encoder
    {
        public static string Encode(string str)
        {
            return Convert.ToBase64String(Encoding.UTF8.GetBytes(str));
        }

        public static string Encode(byte[] data)
        {
            return Convert.ToBase64String(data);
        }


        public static string Decode(string str)
        {
            return Encoding.UTF8.GetString(Convert.FromBase64String(str));
        }
    }

    public enum GrantType
    {
        ClientCredentials,
        AuthorizationCode,
        Implicit,
        ResourceOwner,
    }

    public class TokenIssuerOptions
    {
        public int ExpiresInSeconds { get; set; } = 3600;
        public ITokenIssuer TokenIssuer { get; set; }
        public IClientValidator ClientValidator { get; set; }
        public ITokenGenerator TokenGenerator { get; set; }
        public IClaimGenerator ClaimGenerator { get; set; }
        public ISecurityKeyProvider SecurityKeyProvider { get; set; }
        public IClientStore ClientStore { get; set; }
    }
}