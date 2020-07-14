namespace OAuth2Net.Secret
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
