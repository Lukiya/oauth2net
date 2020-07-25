using System;
using System.Text;

namespace OAuth2Net
{
    public static class Base64Encoder
    {
        public static string EncodeToString(string str)
        {
            return Convert.ToBase64String(Encoding.UTF8.GetBytes(str));
        }

        public static string EncodeToString(byte[] data)
        {
            return Convert.ToBase64String(data);
        }


        public static string DecodeToString(string str)
        {
            return Encoding.UTF8.GetString(Convert.FromBase64String(str));
        }

        public static byte[] DecodeToBytes(string str)
        {
            return Convert.FromBase64String(str);
        }
    }
}