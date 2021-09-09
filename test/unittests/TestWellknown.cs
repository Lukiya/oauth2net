using OAuth2NetCore;
using OAuth2NetCore.Model;
using OAuth2NetCore.Security;

namespace auth2net {
    public class TestWellknown : IWellknown {
        private readonly IJsonWebKeyProvider _jsonWebKeyProvider;

        public TestWellknown(IJsonWebKeyProvider jsonWebKeyProvider) {
            _jsonWebKeyProvider = jsonWebKeyProvider;
        }

        public OpenIDConfig GetOpenIDCOnfig() {
            return new OpenIDConfig {
                issuer = "https://dp.syncecom.co",
                jwks_uri = "https://dp.syncecom.co/.well-known/openid-configuration/jwks",
                authorization_endpoint = "https://dp.syncecom.co/connect/authorize",
                token_endpoint = "https://dp.syncecom.co/connect/token",
                userinfo_endpoint = "https://dp.syncecom.co/connect/userinfo",
                end_session_endpoint = "https://dp.syncecom.co/connect/endsession",
                check_session_iframe = "https://dp.syncecom.co/connect/checksession",
                revocation_endpoint = "https://dp.syncecom.co/connect/revocation",
                introspection_endpoint = "https://dp.syncecom.co/connect/introspect",
                device_authorization_endpoint = "https://dp.syncecom.co/connect/deviceauthorization",
                frontchannel_logout_supported = true,
                frontchannel_logout_session_supported = true,
                backchannel_logout_supported = true,
                backchannel_logout_session_supported = true,
                scopes_supported = new string[] { "passport" },
                claims_supported = new string[] { "sub", "name", "family_name", "given_name", "middle_name", "nickname", "preferred_username", "profile", "picture", "website", "gender", "birthdate", "zoneinfo", "locale", "updated_at" },
                grant_types_supported = new string[] { "authorization_code", "client_credentials", "refresh_token", "implicit", "password" },
                response_types_supported = new string[] { "code", "token", "code token" },
                response_modes_supported = new string[] { "query" },
                token_endpoint_auth_methods_supported = new string[] { "client_secret_post", "client_secret_basic", "client_secret_jwt", "private_key_jwt" },
                id_token_signing_alg_values_supported = new string[] { "PS256" },
                subject_types_supported = new string[] { "public" },
                code_challenge_methods_supported = new string[] { "S256" },
                request_parameter_supported = true,
            };
        }

        public JsonWebKey GetOpenIDJsonWebKey() {
            return _jsonWebKeyProvider.GetJsonWebKey();
        }
    }
}
