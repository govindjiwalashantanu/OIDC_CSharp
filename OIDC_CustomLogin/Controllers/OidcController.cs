using log4net;
using RestSharp;
using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Linq;
using System.Web;
using System.Web.Mvc;
using System.Configuration;

using System.Text;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using System.Security.Cryptography;
using Newtonsoft.Json.Linq;
using ASCO_Oidc.Models;
using ASCO_Oidc.Services;
using System.Web.Routing;
//using System.IdentityModel.Tokens.Jwt;
using System.IdentityModel.Tokens;
using System.Security.Cryptography.X509Certificates;

namespace ASCO_Oidc.Controllers
{
    public class OidcController : Controller
    {
        ILog logger = log4net.LogManager.GetLogger(System.Reflection.MethodBase.GetCurrentMethod().DeclaringType);
        // ILog logger = LogManager.GetLogger("SpecialLogFile");

        NameValueCollection appSettings = ConfigurationManager.AppSettings;

        // Org settings for primary Org
        private static string primaryOrgUrl = ConfigurationManager.AppSettings["okta.ApiUrl"];
        private static string primaryOrgApiToken = ConfigurationManager.AppSettings["okta.ApiToken"];
        private OktaOidcHelper oktaOidcHelper = new OktaOidcHelper(primaryOrgUrl, primaryOrgApiToken);




        [HttpGet]
        public ActionResult Endpoint_Service()
        {
            //Default endoint for Custom Authorization Server
            logger.Debug("Get OIDC Endpoint_Service");
            return RedirectToAction("UnprotectedLanding", "AltLanding");
        }


        [HttpGet]
        public ActionResult Endpoint_Web(string code, string state)
        {
            //use this for auth code workflow
            logger.Debug("Get OIDC Endpoint_Web");
            // set parameters
            string relayState = Request["relayState"];
            if (string.IsNullOrEmpty(relayState) && Request.QueryString["RelayState"] != null)
            {
                relayState = Request.QueryString["RelayState"];
            }
            else if (string.IsNullOrEmpty(relayState) && Request.QueryString["fromURI"] != null)
            {
                relayState = Request.QueryString["fromURI"];
            }
            else if (string.IsNullOrEmpty(relayState) && TempData["relayState"] != null)
            {
                relayState = (string)TempData["relayState"];
            }
            TempData["relayState"] = relayState;

            logger.Debug(" code = " + code + " state " + state);

            string error = null;
            string error_description = null;
            string token_type = null;
            string scope = null;
            string id_token_status = null;
            string idToken = null;
            string access_token_status = null;
            string accessToken = null;
            string refresh_token_status = null;
            string refreshToken = null;
            string jsonPayload = null;
            IRestResponse<TokenRequestResponse> response = null;
            OidcIdToken oidcIdToken = new OidcIdToken();
            OidcAccessToken oidcAccessToken = new OidcAccessToken();
            string basicAuth = appSettings["oidc.spintweb.clientId"] + ":" + appSettings["oidc.spintweb.clientSecret"];

            var bytesBasicAuth = System.Text.Encoding.UTF8.GetBytes(basicAuth);
            string encodedBasicAuth = System.Convert.ToBase64String(bytesBasicAuth);


            try
            {
                //var client = new RestClient(MvcApplication.apiUrl + "/oauth2/v1/token");
                var client = new RestClient(appSettings["oidc.AuthServer"] + "/v1/token");
                var request = new RestRequest(Method.POST);
                request.AddHeader("Accept", "application/json");
                request.AddHeader("Content-Type", "application/x-www-form-urlencoded");
                request.AddHeader("Authorization", " Basic " + encodedBasicAuth);
                request.AddQueryParameter("grant_type", "authorization_code");
                request.AddQueryParameter("code", code);
                request.AddQueryParameter("redirect_uri", appSettings["oidc.spintweb.RedirectUri"]);
                response = client.Execute<TokenRequestResponse>(request);
                error = response.Data.error;
                error_description = response.Data.error_description;
                token_type = response.Data.token_type;
                scope = response.Data.scope;

                if (response.Data.id_token != null)
                {
                    id_token_status = "id_token present";
                    idToken = response.Data.id_token;
                    TempData["idToken"] = idToken;
                    string clientId = appSettings["oidc.spintweb.clientId"];
                    string issuer = appSettings["oidc.Issuer"];
                    string audience = appSettings["oidc.spintweb.clientId"];
                    jsonPayload = oktaOidcHelper.DecodeAndValidateIdToken(idToken, clientId, issuer, audience);
                    if (jsonPayload.Contains("Failure"))
                    {
                        TempData["errMessage"] = "Invalid ID Token!";
                    }
                    else
                    {
                        // TempData["errMessage"] = jsonPayload;
                        System.IdentityModel.Tokens.JwtSecurityToken tokenReceived = new System.IdentityModel.Tokens.JwtSecurityToken(idToken);
                        oidcIdToken = Newtonsoft.Json.JsonConvert.DeserializeObject<OidcIdToken>(jsonPayload);
                    }
                }
                else
                {
                    id_token_status = "id_token NOT present";
                }

                if (response.Data.access_token != null)
                {
                    accessToken = response.Data.access_token;
                    access_token_status = "access_token present";
                    TempData["accessToken"] = response.Data.access_token;
                    string clientId = appSettings["oidc.spintweb.clientId"];
                    string issuer = appSettings["oidc.Issuer"];
                    //audience if different when custom Authorization Server
                    string audience = null;
                    if (appSettings["oidc.chooseAuthServer"] == "default")
                    {
                        audience = appSettings["oidc.Issuer"];
                    }
                    else
                    {
                        audience = appSettings["oidc.customAuthServer.RedirectUri"];
                    }
                    jsonPayload = oktaOidcHelper.DecodeAndValidateIdToken(accessToken, clientId, issuer, audience);

                    System.IdentityModel.Tokens.JwtSecurityToken tokenReceived2 = new System.IdentityModel.Tokens.JwtSecurityToken(accessToken);
                }
                else
                {
                    access_token_status = "access_token NOT present";
                }

                if (response.Data.refresh_token != null)
                {
                    refreshToken = response.Data.refresh_token;
                    refresh_token_status = "refresh_token present";
                    TempData["refreshToken"] = response.Data.refresh_token;
                    
                }
                else
                {
                    refresh_token_status = "refresh_token NOT present";
                }
            }
            catch (Exception ex)
            {

                logger.Error(ex.ToString());
            }

            if (error != null)
            {

                TempData["errMessage"] = "OIDC_Get Oauth Endpoint_Web error " + error_description;
                TempData["oktaOrg"] = MvcApplication.apiUrl;
                //TempData["token"] = MvcApplication.apiToken;
                return RedirectToAction("UnprotectedLanding", "AltLanding");
            }
            else
            {

                TempData["errMessage"] = "OIDC_Get Oauth Endpoint_Web SUCCESS token_type = " + token_type + " scope = " + scope + " : " + id_token_status + " : " + access_token_status + " oktaId = " + oidcIdToken.sub;
                TempData["oktaOrg"] = MvcApplication.apiUrl;
                //TempData["token"] = MvcApplication.apiToken;
                return RedirectToAction("AuthCodeLanding", "AltLanding");

            }

        }



        [HttpPost]
        public ActionResult Endpoint_Native()
        {
            //use this for implicit workflow
            logger.Debug("Post OIDC Endpoint_Native");
            // set parameters
            string relayState = Request["relayState"];
            if (string.IsNullOrEmpty(relayState) && Request.QueryString["RelayState"] != null)
            {
                relayState = Request.QueryString["RelayState"];
            }
            else if (string.IsNullOrEmpty(relayState) && Request.QueryString["fromURI"] != null)
            {
                relayState = Request.QueryString["fromURI"];
            }
            else if (string.IsNullOrEmpty(relayState) && TempData["relayState"] != null)
            {
                relayState = (string)TempData["relayState"];
            }
            TempData["relayState"] = relayState;

            string myState = Request["state"];
            string idToken = Request["id_token"];
            string accessToken = Request["access_token"];
            
            string refreshToken = Request["refresh_token"];
            string tokenType = Request["token_type"];
            string expires = Request["expires_in"];
            string scope = Request["scope"];

            string jsonPayload = null;
            string accessTokenStatus = null;
            string idTokenStatus = null;

            OidcIdTokenMin oidcIdToken = new OidcIdTokenMin();

            if (idToken != null)
            {
                idTokenStatus = " ID Token Present";
                TempData["idToken"] = idToken;
                string clientId = appSettings["oidc.spintnative.clientId"];
                string issuer = appSettings["oidc.Issuer"];
                string audience = appSettings["oidc.spintnative.clientId"];
                jsonPayload = oktaOidcHelper.DecodeAndValidateIdToken(idToken, clientId, issuer, audience);

                if (jsonPayload.Contains("Failure"))
                {
                    TempData["errMessage"] = "Invalid ID Token!";
                }
                else
                {
                    TempData["errMessage"] = "OIDC_Get Oauth Endpoint_Native SUCCESS idToken Valid ";

                    oidcIdToken = Newtonsoft.Json.JsonConvert.DeserializeObject<OidcIdTokenMin>(jsonPayload);
                    System.IdentityModel.Tokens.JwtSecurityToken tokenReceived = new System.IdentityModel.Tokens.JwtSecurityToken(idToken);
                }
            }
            else
            {
                idTokenStatus = " ID Token Not Found";
            }

            if (accessToken != null)
            {
                accessTokenStatus = "access_token Present";
                TempData["accessToken"] = accessToken;
                string clientId = appSettings["oidc.spintnative.clientId"];
                string issuer = appSettings["oidc.Issuer"];
                //audience if different when custom Authorization Server
                string audience = null;
                if (appSettings["oidc.chooseAuthServer"] == "default")
                {
                    audience = appSettings["oidc.Issuer"];
                }
                else
                {
                    audience = appSettings["oidc.customAuthServer.RedirectUri"];
                }


                jsonPayload = oktaOidcHelper.DecodeAndValidateIdToken(accessToken, clientId, issuer, audience);
                System.IdentityModel.Tokens.JwtSecurityToken tokenReceived2 = new System.IdentityModel.Tokens.JwtSecurityToken(accessToken);
            }
            else
            {
                accessTokenStatus = "access_token NOT Found";
            }

            if (accessToken != null || idToken != null)
            {
                TempData["errMessage"] = "OIDC_Get Oauth Endpoint_Native SUCCESS token_type = " + tokenType + " expires = " + expires + " scope = " + scope + " : " + idTokenStatus + " : " + accessTokenStatus + " oktaId = " + oidcIdToken.sub;
                TempData["oktaOrg"] = MvcApplication.apiUrl;
                //TempData["token"] = MvcApplication.apiToken;

                return View("../AltLanding/ImplicitLanding", oidcIdToken);
            }
            else
            {
                TempData["errMessage"] = "OIDC_Get Oauth Endpoint_Native Error token_type = " + tokenType + " expires = " + expires + " scope = " + scope + " : " + idTokenStatus + " : " + accessTokenStatus + " oktaId = " + oidcIdToken.sub;
                TempData["oktaOrg"] = MvcApplication.apiUrl;
                //TempData["token"] = MvcApplication.apiToken;
                return View("../AltLanding/UnprotectedLanding");
            }


        }


        [HttpPost]
        public ActionResult Endpoint_SetSession()
        {
            //use this for implicit workflow
            logger.Debug("Post OIDC Endpoint_SetSession");
            // set parameters
            string relayState = Request["relayState"];
            if (string.IsNullOrEmpty(relayState) && Request.QueryString["RelayState"] != null)
            {
                relayState = Request.QueryString["RelayState"];
            }
            else if (string.IsNullOrEmpty(relayState) && Request.QueryString["fromURI"] != null)
            {
                relayState = Request.QueryString["fromURI"];
            }
            else if (string.IsNullOrEmpty(relayState) && TempData["relayState"] != null)
            {
                relayState = (string)TempData["relayState"];
            }
            TempData["relayState"] = relayState;

            string myState = Request["state"];
            string idToken = Request["id_token"];
            string accessToken = Request["access_token"];
            string tokenType = Request["token_type"];
            string expires = Request["expires_in"];
            string scope = Request["scope"];

            string jsonPayload = null;
            string accessTokenStatus = null;
            string idTokenStatus = null;

            OidcIdToken oidcIdToken = new OidcIdToken();

            if (idToken != null)
            {
                idTokenStatus = " ID Token Present";
                TempData["idToken"] = idToken;
                string clientId = appSettings["oidc.spintnative.clientId"];
                string issuer = appSettings["oidc.Issuer"];
                string audience = appSettings["oidc.spintnative.clientId"];
                jsonPayload = oktaOidcHelper.DecodeAndValidateIdToken(idToken, clientId, issuer, audience);

                if (jsonPayload.Contains("Failure"))
                {
                    TempData["errMessage"] = "Invalid ID Token!";
                }
                else
                {
                    TempData["errMessage"] = "OIDC_Get Oauth Endpoint_Native SUCCESS idToken Valid ";

                    oidcIdToken = Newtonsoft.Json.JsonConvert.DeserializeObject<OidcIdToken>(jsonPayload);
                    System.IdentityModel.Tokens.JwtSecurityToken tokenReceived = new System.IdentityModel.Tokens.JwtSecurityToken(idToken);
                }
            }
            else
            {
                idTokenStatus = " ID Token Not Found";
            }

            if (accessToken != null)
            {
                accessTokenStatus = "access_token Present";
                TempData["accessToken"] = accessToken;
                string clientId = appSettings["oidc.spintnative.clientId"];
                string issuer = appSettings["oidc.Issuer"];
                //audience if different when custom Authorization Server
                string audience = null;
                if (appSettings["oidc.chooseAuthServer"] == "default")
                {
                    audience = appSettings["oidc.Issuer"];
                }
                else
                {
                    audience = appSettings["oidc.customAuthServer.RedirectUri"];
                }

                jsonPayload = oktaOidcHelper.DecodeAndValidateIdToken(accessToken, clientId, issuer, audience);
                System.IdentityModel.Tokens.JwtSecurityToken tokenReceived2 = new System.IdentityModel.Tokens.JwtSecurityToken(accessToken);
            }
            else
            {
                accessTokenStatus = "access_token NOT Found";
            }

            if (accessToken != null || idToken != null)
            {
                TempData["errMessage"] = "OIDC_Get Oauth Endpoint_Native SUCCESS token_type = " + tokenType + " expires = " + expires + " scope = " + scope + " : " + idTokenStatus + " : " + accessTokenStatus + " oktaId = " + oidcIdToken.sub;
                TempData["oktaOrg"] = MvcApplication.apiUrl;
                //TempData["token"] = MvcApplication.apiToken;

                return View("../AltLanding/ImplicitLanding", oidcIdToken);
            }
            else
            {
                TempData["errMessage"] = "OIDC_Get Oauth Endpoint_Native Error token_type = " + tokenType + " expires = " + expires + " scope = " + scope + " : " + idTokenStatus + " : " + accessTokenStatus + " oktaId = " + oidcIdToken.sub;
                TempData["oktaOrg"] = MvcApplication.apiUrl;
                //TempData["token"] = MvcApplication.apiToken;
                return View("../AltLanding/UnprotectedLanding");
            }


        }



        [HttpGet]
        public ActionResult RenewAccessToken()
        {
            //string idToken = TempData["idToken"].ToString();
            string accessToken = TempData["accessToken"].ToString();
            string refreshToken = TempData["refreshToken"].ToString();
            //logger.Debug(" code = " + code + " state " + state);
            TempData["accessToken"] = accessToken;
            //TempData["idToken"] = idToken;
            TempData["refreshToken"] = refreshToken;
            string error = null;
            string error_description = null;
            string token_type = null;
            string scope = null;
            string id_token_status = null;
 
            string access_token_status = null;
 
            string refresh_token_status = null;

            string jsonPayload = null;
            IRestResponse<TokenRequestResponse> response = null;
            string basicAuth = appSettings["oidc.spintweb.clientId"] + ":" + appSettings["oidc.spintweb.clientSecret"];

            var bytesBasicAuth = System.Text.Encoding.UTF8.GetBytes(basicAuth);
            string encodedBasicAuth = System.Convert.ToBase64String(bytesBasicAuth);


            try
            {
                //var client = new RestClient(MvcApplication.apiUrl + "/oauth2/v1/token");
                var client = new RestClient(appSettings["oidc.AuthServer"] + "/v1/token");
                var request = new RestRequest(Method.POST);
                // request.AddHeader("cache-control", "no-cache");
                request.AddHeader("Accept", "application/json");
                request.AddHeader("Content-Type", "application/x-www-form-urlencoded");
                request.AddHeader("Authorization", " Basic " + encodedBasicAuth);
                request.AddQueryParameter("grant_type", "refresh_token");
                request.AddQueryParameter("refresh_token", refreshToken);
                request.AddQueryParameter("redirect_uri", appSettings["oidc.spintweb.RedirectUri"]);
                response = client.Execute<TokenRequestResponse>(request);
                error = response.Data.error;
                error_description = response.Data.error_description;
                token_type = response.Data.token_type;
                scope = response.Data.scope;



                if (response.Data.access_token != null)
                {
                    accessToken = response.Data.access_token;
                    TempData["accessToken"] = accessToken;
                    string clientId = appSettings["oidc.spintweb.clientId"];
                    string issuer = appSettings["oidc.Issuer"];
                    //string audience = appSettings["oidc.customAuthServer.RedirectUri"];
                    string audience = appSettings["oidc.spintweb.RedirectUri"];
                    jsonPayload = oktaOidcHelper.DecodeAndValidateIdToken(accessToken, clientId, issuer, audience);
                }
                else
                {
                    access_token_status = "access_token NOT present";
                }

                if (response.Data.refresh_token != null)
                {
                    refreshToken = response.Data.refresh_token;
                    refresh_token_status = "refresh_token present";
                    TempData["refreshToken"] = refreshToken;
                }
                else
                {
                    refresh_token_status = "refresh_token NOT present";
                }
            }
            catch (Exception ex)
            {

                //logger.Error(ex.ToString());
            }

            if (accessToken != null)
            {

                //TempData["idToken"] = idToken;

                return RedirectToAction("InitiateSendWebApi_wToken", "AltLanding");
            }
            else
            {
                logger.Debug(error + " : " + error_description);
                TempData["errMessage"] = error + " : " + error_description;
                return View("../AltLanding/WebApiA");
            }

        }


    }
}