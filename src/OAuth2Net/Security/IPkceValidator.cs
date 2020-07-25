namespace OAuth2Net.Security
{
    public interface IPkceValidator
    {
        bool Verify(string codeVerifier, string codeChanllenge, string codeChanllengeMethod);
    }
}
