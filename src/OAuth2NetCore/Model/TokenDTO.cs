using System.Text.Json.Serialization;

namespace OAuth2NetCore.Model
{
    public class TokenDTO
    {
        [JsonPropertyName(OAuth2Consts.Form_AccessToken)]
        public string AccessToken { get; set; }
        [JsonPropertyName(OAuth2Consts.Form_RefreshToken)]
        public string RefreshToken { get; set; }
        [JsonPropertyName(OAuth2Consts.Form_ExpiresIn)]
        public int AccessTokenExpiresIn { get; set; }
        [JsonPropertyName(OAuth2Consts.Form_RefreshTokenExpiresIn)]
        public int RefreshTokenExpiresIn { get; set; }
        [JsonPropertyName(OAuth2Consts.Form_Scope)]
        public string Scopes { get; set; }
        [JsonPropertyName(OAuth2Consts.Form_TokenType)]
        public string TokenType { get; set; }
    }
}
