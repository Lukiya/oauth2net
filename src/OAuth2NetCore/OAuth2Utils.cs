﻿using Microsoft.IdentityModel.Tokens;
using System.Security.Cryptography;
using System.Text;

namespace OAuth2NetCore {
    public static class OAuth2Utils
    {
        public static string ToSHA256Base64URL(string str)
        {
            byte[] bytes;
            using (var sha256 = SHA256.Create())
            {
                bytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(str));
            }

            return Base64UrlEncoder.Encode(bytes);
        }
    }
}
