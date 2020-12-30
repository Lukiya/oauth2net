﻿using System;

namespace OAuth2NetCore.Model
{
    public class TokenRequestInfo
    {
        public string ClientID { get; set; }
        public string Scopes { get; set; }
        public string RedirectUri { get; set; }
        public string Username { get; set; }
        public string CodeChanllenge { get; set; }
        public string CodeChanllengeMethod { get; set; }
        public DateTimeOffset RefreshTokenExpire { get; set; }
    }
}
