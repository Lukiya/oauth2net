using Microsoft.IdentityModel.Tokens;
using System;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace OAuth2Net.Security
{
    public interface ICertProvider
    {
        SecurityKey GetSecurityKey();
    }

    public class FileCertProvider : ICertProvider
    {
        private readonly X509SecurityKey _securityKey;

        public FileCertProvider(string pfxPath, string pfxPassword)
        {
            var x509Cert = new X509Certificate2(pfxPath, pfxPassword);
            _securityKey = new X509SecurityKey(x509Cert);
        }

        public SecurityKey GetSecurityKey() => _securityKey;
    }
}
