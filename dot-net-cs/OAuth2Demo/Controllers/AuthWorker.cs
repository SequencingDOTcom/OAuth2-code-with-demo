using System;
using System.IO;
using System.Net;
using System.Text;
using System.Web;
using RestSharp;

namespace OAuth2Demo.Controllers
{
    /// <summary>
    /// AuthWorker class is responsible for working with OAuth authorization server, retrieving access tokens and refreshing them
    /// </summary>
    public class AuthWorker
    {
        private readonly string oAuthUrl;
        private readonly string redirectUrl;
        private readonly string appId;
        private readonly string secret;

        public AuthWorker(string oAuthUrl, string redirectUrl, string secret, string appId)
        {
            this.oAuthUrl = oAuthUrl;
            this.redirectUrl = redirectUrl;
            this.secret = secret;
            this.appId = appId;
        }

        /// <summary>
        /// RefreshToken method performs authtoken refresh through previously acquired refreshToken
        /// </summary>
        /// <param name="refreshToken"></param>
        /// <returns></returns>
        public AuthInfo RefreshToken(string refreshToken)
        {
            var _webRequest = CreateRq();
            try
            {
                using (var _str = _webRequest.GetRequestStream())
                using (var _sw = new StreamWriter(_str))
                {
                    _sw.Write("grant_type={0}&refresh_token={1}", "refresh_token", refreshToken);
                    _sw.Flush();
                }
                var _webResponse = _webRequest.GetResponse();
                using (var _stream = _webResponse.GetResponseStream())
                using (var _sr = new StreamReader(_stream))
                {
                    var _readToEnd = _sr.ReadToEnd();
                    var _res = SimpleJson.DeserializeObject<TokenInfo>(_readToEnd);
                    _res.life_time = DateTime.Now.AddSeconds(Double.Parse(_res.expires_in));
                    return new AuthInfo { Success = true, Token = _res };
                }
            }
            catch (WebException _ex)
            {
                using (var _rs = _ex.Response.GetResponseStream())
                using (var _sr = new StreamReader(_rs))
                {
                    var _readToEnd = _sr.ReadToEnd();
                    return new AuthInfo { Success = false, ErrorMessage = "Error while refreshing token, HTTP:" + _ex.Status + ":" + _readToEnd };
                }
            }
        }

        public TokenInfo GetToken(TokenInfo info)
        {
            if (info.life_time < DateTime.Now)
                info = RefreshToken(info.refresh_token).Token;
            return info;

        }

        private HttpWebRequest CreateRq()
        {
            var _webRequest = (HttpWebRequest) WebRequest.Create(oAuthUrl + "?q=oauth2/token");
            _webRequest.Method = "POST";
            _webRequest.Headers.Add("Authorization",
                "Basic " + Convert.ToBase64String(ASCIIEncoding.ASCII.GetBytes(appId + ":" + secret)));
            _webRequest.ContentType = "application/x-www-form-urlencoded";
            _webRequest.UserAgent = "OAUTH-DEMO-APP";
            return _webRequest;
        }

        /// <summary>
        /// Second step in OAuth initial authorization sequence. 
        /// </summary>
        /// <param name="code">code parameter acquired from OAuth server</param>
        /// <returns>AuthInfo object which represents the final result of authorization</returns>
        public AuthInfo GetAuthInfo(string code)
        {
            var _webRequest = CreateRq();
            try
            {
                using (var _str = _webRequest.GetRequestStream())
                using (var _sw = new StreamWriter(_str))
                {
                    _sw.Write("grant_type={0}&code={1}&redirect_uri={2}", "authorization_code", code,
                        HttpUtility.UrlEncode(redirectUrl));
                    _sw.Flush();
                }
                var _webResponse = _webRequest.GetResponse();
                using (var _stream = _webResponse.GetResponseStream())
                using (var _sr = new StreamReader(_stream))
                {
                    var _readToEnd = _sr.ReadToEnd();
                    var _res = SimpleJson.DeserializeObject<TokenInfo>(_readToEnd);
                    _res.life_time = DateTime.Now.AddSeconds(Double.Parse(_res.expires_in));
                    return new AuthInfo{Success = true, Token = _res};
                }
            }
            catch (WebException _ex)
            {
                using (var _rs = _ex.Response.GetResponseStream())
                using (var _sr = new StreamReader(_rs))
                {
                    var _readToEnd = _sr.ReadToEnd();
                    return new AuthInfo { Success = false, ErrorMessage = "Error while retrieving token, HTTP:"+_ex.Status+":"+_readToEnd};
                }
            }
        }

        /// <summary>
        /// Retrieves OAuth initial authorization url. Url on which browser should be redirected to.
        /// </summary>
        /// <returns></returns>
        public string GetAuthUrl()
        {
            return oAuthUrl+ "?q=oauth2/authorize&redirect_uri="+redirectUrl+"&response_type=code&state=123&client_id="+appId+"&scope=external";
        }
    }
}