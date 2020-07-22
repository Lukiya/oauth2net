using Microsoft.IdentityModel.Tokens;
using System.Security.Cryptography.X509Certificates;

namespace OAuth2Net.Security
{
    public class X509FileSecurityKeyProvider : ISecurityKeyProvider
    {
        private readonly X509SecurityKey _securityKey;

        public X509FileSecurityKeyProvider(string pfxPath, string pfxPassword)
        {
            var x509Cert = new X509Certificate2(pfxPath, pfxPassword);
            _securityKey = new X509SecurityKey(x509Cert);
        }

        public SecurityKey GetSecurityKey() => _securityKey;
    }
}
