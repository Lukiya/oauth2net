using System;
using System.Text;

namespace OAuth2Net
{
    public static class Consts
    {
        public const string Header_Authorization = "Authorization";
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

        public bool IsSuccess => Message.IsSuccess();
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
}