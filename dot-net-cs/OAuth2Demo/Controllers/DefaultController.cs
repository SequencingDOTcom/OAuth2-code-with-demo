using System.Web.Mvc;

namespace OAuth2Demo.Controllers
{
    public class DefaultController : Controller
    {
        private AuthWorker authWorker = new AuthWorker(Options.OAuthUrl, Options.OAuthRedirectUrl, Options.OAuthSecret, Options.OAuthAppId);
        // GET: Default
        public ActionResult Index()
        {
            return View();
        }

        public ActionResult AuthCallback(string code)
        {
            if (code != null)
            {
                //Retrieving token
                var _authInfo = authWorker.GetAuthInfo(code);
                if (_authInfo.Success)  
                    if (_authInfo.Success)
                    {
                        var _listFiles = new BasicApiWorker(authWorker.GetToken(_authInfo.Token), Options.ApiUrl).ListFiles();
                        return View("FilesList", _listFiles);
                    }           
                return new ContentResult { Content = "Error while retrieving access token:" + _authInfo.ErrorMessage };
            }
            return new ContentResult{Content = "User cancelled the auth sequence"};
        }


        public ActionResult ViewFiles()
        {
            return Redirect(authWorker.GetAuthUrl());
        }        
    }
}