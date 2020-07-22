namespace OAuth2Net.Security
{
    public class NoSecertHash : ISecertHash
    {
        public string Hash(string secert) => secert;
    }
}
