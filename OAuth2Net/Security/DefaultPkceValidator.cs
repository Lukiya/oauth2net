namespace OAuth2Net.Security
{
    public class DefaultPkceValidator : IPkceValidator
    {
        public bool Verify(string codeVerifier, string codeChanllenge, string codeChanllengeMethod)
        {
            bool r = false;

            if (codeChanllengeMethod == OAuth2Consts.Pkce_Plain)
            {
                r = codeVerifier == codeChanllenge;
            }
            else if (codeChanllengeMethod == OAuth2Consts.Pkce_S256)
            {
                var sha256Verifier = OAuth2Utils.SHA256ToBase64URL(codeVerifier);
                r = sha256Verifier == codeChanllenge;
            }

            // not suppor other methods
            return r;
        }
    }
}
