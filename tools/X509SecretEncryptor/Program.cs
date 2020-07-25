using Microsoft.Extensions.Configuration;
using OAuth2Net.Security;
using System;


namespace encryptor
{
    class Program
    {
        static void Main(string[] args)
        {
            var config = new ConfigurationBuilder()
                .AddCommandLine(args)
                .Build();

            var certPath = config.GetValue<string>("CertPath");
            var certPass = config.GetValue<string>("CertPass");
            var mode = config.GetValue<string>("Mode");
            var value = config.GetValue<string>("Value");

            var encryptor = new X509SecretEncryptor(certPath, certPass);

            if (mode == "e")
            {
                var r = encryptor.Encrypt(value);
                Console.WriteLine(r);
            }
            else if (mode == "d")
            {
                var r = encryptor.Decrypt(value);
                Console.WriteLine(r);
            }
        }
    }
}
