using System;

namespace OAuth2Demo.Controllers
{
    /// <summary>
    /// TokenInfo is a data structure holding all authentication related properties
    /// </summary>
    public class TokenInfo
    {
        public string access_token { get; set; }
        public string expires_in { get; set; }
        public string token_type { get; set; }
        public string scope { get; set; }
        public string refresh_token { get; set; }
        public DateTime life_time { get; set; }
    }
}