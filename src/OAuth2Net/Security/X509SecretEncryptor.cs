using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace OAuth2Net.Security
{
    /// <summary>
    /// has secret length limit, it depends on your certificate length
    /// </summary>
    public class X509SecretEncryptor : ISecretEncryptor
    {
        private readonly X509Certificate2 _x509Cert;
        private readonly RSA _publicRsaProvider;
        private readonly RSA _privateRsaProvider;

        public X509SecretEncryptor(string pfxPath, string pfxPassword) : this(new X509Certificate2(pfxPath, pfxPassword))
        {
        }

        public X509SecretEncryptor(X509Certificate2 cert)
        {
            _x509Cert = cert;
            _publicRsaProvider = _x509Cert.GetRSAPublicKey();
            _privateRsaProvider = _x509Cert.GetRSAPrivateKey();
        }

        public string Encrypt(string intput)
        {
            var plainBytes = Encoding.UTF8.GetBytes(intput);
            var encryptedBytes = _publicRsaProvider.Encrypt(plainBytes, RSAEncryptionPadding.Pkcs1);

            return Base64Encoder.EncodeToString(encryptedBytes);
        }

        public string Decrypt(string intput)
        {
            var encryptedBytes = Base64Encoder.DecodeToBytes(intput);

            var plainBytes = _privateRsaProvider.Decrypt(encryptedBytes, RSAEncryptionPadding.Pkcs1);

            var plainText = Encoding.UTF8.GetString(plainBytes);
            return plainText;
        }

        public bool TryDecrypt(string intput, out string output)
        {
            try
            {
                output = Decrypt(intput);
                return true;
            }
            catch
            {
                output = intput;
                return false;
            }
        }
    }
}
