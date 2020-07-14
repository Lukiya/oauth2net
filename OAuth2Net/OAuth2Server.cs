using System;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using OAuth2Net.Client;
using Microsoft.Extensions.Logging;
using Microsoft.AspNetCore.Http;
using Newtonsoft.Json;
using System.Net;
using System.Collections.Generic;
using System.Security.Cryptography;
using OAuth2Net.Secret;

namespace OAuth2Net
{
    public interface IOAuth2Server
    {
        RequestDelegate TokenHandler { get; }
        //Task<MessageResult<IClient>> VerifyClientAsync(string authorzation);
        //Task<MessageResult<IClient>> VerifyClientAsync(string authorzation, string grantType, string scopes);
    }

    public class OAuth2Server : IOAuth2Server
    {
        private readonly ILogger<OAuth2Server> _logger;
        private readonly IClientStore _clientStore;
        private readonly ICertProvider _certProvider;

        public RequestDelegate TokenHandler { get; }

        public OAuth2Server(IClientStore clientStore, ILogger<OAuth2Server> logger, ICertProvider certProvider)
        {
            _logger = logger;
            _clientStore = clientStore;
            _certProvider = certProvider;
            TokenHandler = HandleTokenRequestAsync;
        }

        protected virtual async Task HandleTokenRequestAsync(HttpContext context)
        {
            var authorzation = context.Request.Headers[Consts.Header_Authorization].FirstOrDefault();
            var grantType = context.Request.Form[Consts.Form_GrantType].FirstOrDefault();
            var scopes = context.Request.Form[Consts.Form_Scope].FirstOrDefault();

            var msgResult = await VerifyClientAsync(authorzation, grantType, scopes).ConfigureAwait(false);
            if (!msgResult.IsSuccess)
            {
                context.Response.StatusCode = (int)HttpStatusCode.BadRequest;
                await context.Response.WriteAsync(msgResult.Message).ConfigureAwait(false);
                return;
            }

            var payload = new Dictionary<string, object>();
            payload["client_id"] = msgResult.Result.ID;
            payload["scope"] = scopes.Split(' ');
            switch (grantType)
            {
                case Consts.GrantType_Client:
                    // issue token directly
                    payload["name"] = msgResult.Result.ID;
                    payload["role"] = "1";
                    var token = GenerateToken(payload, 3600);
                    context.Response.ContentType = "application/json;charset=UTF-8";
                    context.Response.Headers.Add("Cache-Control", "no-store");
                    context.Response.Headers.Add("Pragma", "no-cache");
                    await context.Response.WriteAsync(string.Format(Consts.Tmpl_Token1, token, 3600, scopes)).ConfigureAwait(false);
                    break;
                case Consts.GrantType_Code:
                    break;
                case Consts.GrantType_Owner:
                    // verify username & password
                    break;
                case Consts.GrantType_Implicit:
                    break;
                default:
                    context.Response.StatusCode = (int)HttpStatusCode.BadRequest;
                    await context.Response.WriteAsync("invalid grant type").ConfigureAwait(false);
                    break;
            }

        }

        private async Task<MessageResult<IClient>> VerifyClientAsync(string authorzation)
        {
            var r = new MessageResult<IClient>();

            if (string.IsNullOrWhiteSpace(authorzation))
            {
                r.Message = "no authorization header";
                _logger.LogDebug(r.Message);
                return r;
            }

            var authArray = authorzation.Split(' ');
            if (authArray.Length != 2 || string.IsNullOrWhiteSpace(authArray[1]))
            {
                r.Message = "invalid authorization string";
                _logger.LogDebug(r.Message);
                return r;
            }

            var authStr = Base64Encoder.Decode(authArray[1]);
            authArray = authStr.Split(':');

            if (authArray.Length != 2 || string.IsNullOrWhiteSpace(authArray[0]) || string.IsNullOrWhiteSpace(authArray[1]))
            {
                r.Message = "invalid authorization string";
                _logger.LogDebug(r.Message);
                return r;
            }

            var client = await _clientStore.VerifyAsync(authArray[0], authArray[1]).ConfigureAwait(false);
            if (client == null)
            {
                r.Message = "invalid client";
                _logger.LogDebug(r.Message);
                return r;
            }

            r.Result = client;
            return r;
        }

        private async Task<MessageResult<IClient>> VerifyClientAsync(string authorzation, string grantType, string scopes)
        {
            var r = new MessageResult<IClient>();

            if (string.IsNullOrWhiteSpace(grantType))
            {
                r.Message = "no grant type";
                _logger.LogDebug(r.Message);
                return r;
            }

            if (string.IsNullOrWhiteSpace(scopes))
            {
                r.Message = "no scope";
                _logger.LogDebug(r.Message);
                return r;
            }

            var clientResult = await VerifyClientAsync(authorzation).ConfigureAwait(false);
            if (!clientResult.IsSuccess)
                return r;

            if (clientResult.Result.Grants == null || !clientResult.Result.Grants.Contains(grantType))
            {
                r.Message = $"'{grantType}' grant is not allowed for '{clientResult.Result.ID}'";
                _logger.LogDebug(r.Message);
                return r;
            }

            if (clientResult.Result.Scopes == null)
            {
                r.Message = $"no scope is allowed for '{clientResult.Result.ID}'";
                _logger.LogDebug(r.Message);
                return r;
            }

            var scopeArray = scopes.Split(' ');
            var notAllowedScopes = scopeArray.Except(clientResult.Result.Scopes);
            if (notAllowedScopes.Any())
            {
                r.Message = $"scope '{string.Join(", ", notAllowedScopes)}' is allowed for '{clientResult.Result.ID}'";
                _logger.LogDebug(r.Message);
            }

            r.Result = clientResult.Result;
            return r;
        }




        string GenerateToken(IDictionary<string, object> payLoad, int expireSeconds, IDictionary<string, object> header = null)
        {
            if (header == null)
            {
                header = new Dictionary<string, object> { { "alg", "RS256" }, { "typ", "JWT" } };
            }
            //添加jwt可用时间（应该必须要的）
            var now = DateTime.UtcNow;
            payLoad["nbf"] = ToUnixEpochTime(now);//可用时间起始
            payLoad["exp"] = ToUnixEpochTime(now.AddSeconds(expireSeconds));//可用时间结束

            var encodedHeader = Base64Encoder.Encode(JsonConvert.SerializeObject(header));
            var encodedPayload = Base64Encoder.Encode(JsonConvert.SerializeObject(payLoad));

            var keyBytes = _certProvider.GetPrivateKey();
            var hs256 = new HMACSHA256(keyBytes);
            var encodedSignature = Base64Encoder.Encode(hs256.ComputeHash(Encoding.UTF8.GetBytes($"{encodedHeader}.{encodedPayload}")));

            var encodedJwt = $"{encodedHeader}.{encodedPayload}.{encodedSignature}";
            return encodedJwt;
        }

        long ToUnixEpochTime(DateTime dateTime)
        {
            var ts = dateTime.Subtract(new DateTime(1970, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc));
            return Convert.ToInt64(ts.TotalSeconds);
        }
    }
}
