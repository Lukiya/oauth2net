using System;
using System.Text;

namespace OAuth2Net
{
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

        public static byte[] DecodeBytes(string str)
        {
            return Convert.FromBase64String(str);
        }
    }
}