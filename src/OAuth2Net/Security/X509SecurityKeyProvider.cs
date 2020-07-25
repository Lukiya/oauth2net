﻿using Microsoft.IdentityModel.Tokens;
using System.Security.Cryptography.X509Certificates;

namespace OAuth2Net.Security
{
    public class X509SecurityKeyProvider : ISecurityKeyProvider
    {
        private readonly X509SecurityKey _securityKey;

        public X509SecurityKeyProvider(string pfxPath, string pfxPass) : this(new X509Certificate2(pfxPath, pfxPass))
        {
        }

        public X509SecurityKeyProvider(X509Certificate2 cert)
        {
            _securityKey = new X509SecurityKey(cert);
        }


        public SecurityKey GetSecurityKey() => _securityKey;
    }
}
