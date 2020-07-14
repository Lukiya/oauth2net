using System;
using System.IO;

namespace OAuth2Net.Secret
{
    public interface ICertProvider
    {
        byte[] GetCertificate();
        byte[] GetPrivateKey();
    }

    public class FileCertProvider : ICertProvider
    {
        private readonly byte[] _cert;
        private readonly byte[] _key;

        public FileCertProvider(string certPth, string keyPath)
        {
            _cert = File.ReadAllBytes(certPth);
            _key = File.ReadAllBytes(keyPath);
        }

        public byte[] GetCertificate() => _cert;

        public byte[] GetPrivateKey() => _key;
    }
}
