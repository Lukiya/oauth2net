namespace OAuth2Net.Security
{
    public interface ISecertHash
    {
        string Hash(string secert);
    }

    public class NoSecertHash : ISecertHash
    {
        public string Hash(string secert) => secert;
    }
}
