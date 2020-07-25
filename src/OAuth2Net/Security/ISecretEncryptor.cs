namespace OAuth2Net.Security
{
    public interface ISecretEncryptor
    {
        string Encrypt(string input);
        string Decrypt(string input);
        bool TryDecrypt(string input, out string output);
    }
}
