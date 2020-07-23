using System;
using System.Security.Cryptography;
using System.Text;

namespace OAuth2Net
{
    public static class OAuth2Utils
    {
        public static string ToBase64URL(byte[] bytes)
        {
            var r = Convert.ToBase64String(bytes)
                  .TrimEnd('=')
                  .Replace('+', '-')
                  .Replace('/', '_');

            return r;
        }

        public static string ToSHA256Base64URL(string str)
        {
            byte[] bytes;
            using (var sha256 = SHA256.Create())
            {
                bytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(str));
            }

            return ToBase64URL(bytes);
        }
    }
}
