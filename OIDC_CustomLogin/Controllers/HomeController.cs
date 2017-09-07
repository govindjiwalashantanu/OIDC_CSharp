using log4net;
using Okta.Core.Models;
using RestSharp;
using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Configuration;
using System.Linq;
using System.Web;
using System.Web.Mvc;
using ASCO_Oidc.Models;
using ASCO_Oidc.Services;
using Okta.Core;
using Okta.Core.Clients;

namespace ASCO_Oidc.Controllers
{
    public class HomeController : Controller
    {

        ILog logger = log4net.LogManager.GetLogger(System.Reflection.MethodBase.GetCurrentMethod().DeclaringType);
        // ILog logger = LogManager.GetLogger("SpecialLogFile");

        NameValueCollection appSettings = ConfigurationManager.AppSettings;

        // Org settings for primary Org
        private static string primaryOrgUrl = ConfigurationManager.AppSettings["okta.ApiUrl"];
        private static string primaryOrgApiToken = ConfigurationManager.AppSettings["okta.ApiToken"];
 
        private OktaUserMgmt oktaUserMgmt = new OktaUserMgmt(primaryOrgUrl, primaryOrgApiToken);
        private OktaAuthMgmt oktaAuthMgmt = new OktaAuthMgmt(primaryOrgUrl, primaryOrgApiToken);
        private OktaSessionMgmt oktaSessionMgmt = new OktaSessionMgmt(primaryOrgUrl, primaryOrgApiToken);
        private OktaOidcHelper oktaOidcHelper = new OktaOidcHelper(primaryOrgUrl, primaryOrgApiToken);


        [HttpGet]
        public ActionResult Error()
        {
            logger.Debug("okta error message redirect");
            return View();
        }


        [HttpGet]
        public ActionResult Login()
        {
            // set relayState 
            //string relayState = Request["relayState"];
            //if (string.IsNullOrEmpty(relayState) && Request.QueryString["RelayState"] != null)
            //{
            //    relayState = Request.QueryString["RelayState"];
            //}
            //else if (string.IsNullOrEmpty(relayState) && TempData["relayState"] != null)
            //{
            //    relayState = (string)TempData["relayState"];
            //}
            //TempData["relayState"] = relayState;

            // GetInfoResponse rspData = new GetInfoResponse();
            TempData["oktaOrg"] = MvcApplication.apiUrl;
            //TempData["token"] = MvcApplication.apiToken;
            return View("Login");
        }


        [HttpPost]
        public ActionResult Route()
        {

            string userName = Request["userName"];
            string passWord = Request["passWord"];
            string authnlogin_but = Request["authnlogin_but"];
            string oidclogin_but = Request["oidclogin_but"];
            string oidc_but = Request["oidc_but"];
            string location = Request["location"];
            string myStatus = null;
            string myStateToken;
            string mySessionToken;
            string myRelayState = null;
            string myOktaId = null;
            AuthResponse userAuthClientRsp;

            // set relayState 
            //string relayState = Request["relayState"];
            //if (string.IsNullOrEmpty(relayState) && Request.QueryString["RelayState"] != null)
            //{
            //    relayState = Request.QueryString["RelayState"];
            //}
            //else if (string.IsNullOrEmpty(relayState) && TempData["relayState"] != null)
            //{
            //    relayState = (string)TempData["relayState"];
            //}
            //TempData["relayState"] = relayState;

            if (authnlogin_but == "Authn Sign In")
            {

                OktaClient oktaClient = new OktaClient(MvcApplication.apiToken,MvcApplication.apiUrl);
                try
                {
                    var usersClient = oktaClient.GetUsersClient();
                    var authClient = oktaClient.GetAuthClient();
                    userAuthClientRsp = authClient.Authenticate(username: userName, password: passWord, relayState: myRelayState);
                    logger.Debug("thisAuth status " + userAuthClientRsp.Status);
                    myStatus = userAuthClientRsp.Status;
                    myStateToken = userAuthClientRsp.StateToken;
                    mySessionToken = userAuthClientRsp.SessionToken;
                    if (userAuthClientRsp.Embedded.User != null)
                    {
                        myOktaId = userAuthClientRsp.Embedded.User.Id;
                    }

                }
                catch (OktaException ex)
                {
                    if (ex.ErrorCode == "E0000004")
                    {
                        logger.Debug("Invalid Credentials for User: " + userName);
                        TempData["errMessage"] = "Invalid Credentials for User: " + userName;
                    }
                    else if (ex.ErrorCode == "E0000085")
                    {
                        logger.Debug("Access Denied by Polciy for User: " + userName);
                        //   TempData["errMessage"] = "Access Denied by Polciy for User: " + userName;
                        TempData["errMessage"] = appSettings["aicpa.DeniedNoteText"];
                    }
                    else
                    {
                        logger.Error(userName + " = " + ex.ErrorCode + ":" + ex.ErrorSummary);
                        // generic failure
                        TempData["errMessage"] = "Sign in process failed!";
                    }
                    TempData["userName"] = userName;
                    return RedirectToAction("Login");
                }

                switch (myStatus)
                {

                    case "PASSWORD_WARN":  //password about to expire
                        logger.Debug("PASSWORD_WARN ");
                        //no action required
                        break;

                    case "PASSWORD_EXPIRED":  //password has expired
                        logger.Debug("PASSWORD_EXPIRED ");
                        break;

                    case "RECOVERY":  //user has requested a recovery token
                        logger.Debug("RECOVERY ");
                        //find which recovery mode sms, email is being used
                        //POST to next link
                        break;

                    case "RECOVERY_CHALLENGE":  //user must verify factor specific recovery challenge
                        logger.Debug("RECOVERY_CHALLENGE ");
                        //verify the recovery factor
                        //POST to verify link
                        break;

                    case "PASSWORD_RESET":     //user satified recovery and must now set password
                        logger.Debug("PASSWORD_RESET ");

                        //reset users password
                        //POST to next link
                        break;

                    case "LOCKED_OUT":  //user account is locked, unlock required
                        logger.Debug("LOCKED_OUT ");
                        break;

                    case "MFA_ENROLL":   //user must select and enroll an available factor 
                        logger.Debug("MFA_ENROLL ");
                        break;

                    case "MFA_ENROLL_ACTIVATE":   //user must activate the factor to complete enrollment
                        logger.Debug("MFA_ENROLL_ACTIVATE ");
                        //user must activate the factor
                        //POST to next link
                        break;

                    case "MFA_REQUIRED":    //user must provide second factor with previously enrolled factor
                        logger.Debug("MFA_REQUIRED ");
                        break;

                    case "MFA_CHALLENGE":      //use must verify factor specifc challenge
                        logger.Debug("MFA_CHALLENGE ");
                        break;

                    case "SUCCESS":      //authentication is complete
                        logger.Debug("SUCCESS");
                        TempData["errMessage"] = "Authn Login Successful ";
                        TempData["oktaOrg"] = MvcApplication.apiUrl;
                        //TempData["token"] = MvcApplication.apiToken;
                        string landingPage = null;
                        landingPage = location + "/AltLanding/UnprotectedLanding";
                        //if (string.IsNullOrEmpty(relayState))
                        //{
                        //    landingPage = location + "/AltLanding/UnprotectedLanding";
                        //}
                        //else
                        //{
                        //    landingPage = relayState;
                        //}


                        //option 1
                        //string redirectUrl = oktaSessionMgmt.SetSessionCookie(mySessionToken,landingPage);
                        //return Redirect(redirectUrl);

                        //option 2 - build redirectURL
                        //System.Text.StringBuilder redirectUrl = new System.Text.StringBuilder();
                        //string destLink = location + "/AltLanding/UnprotectedLanding";
                        //redirectUrl.Append(MvcApplication.apiUrl);
                        ////redirectUrl.Append("/login/sessionCookieRedirect?token=" + mySessionToken);
                        //redirectUrl.Append("/login/sessionCookieRedirect?checkAccountSetupComplete=true&token=" + mySessionToken);
                        //string encodedURL = HttpUtility.UrlEncode(destLink);
                        //redirectUrl.Append("&redirectUrl=" + encodedURL);
                        //return Redirect(redirectUrl.ToString());

                        //option 3 get session first, then set cookie
                        Session oktaSession = new Okta.Core.Models.Session();
                        oktaSession = oktaSessionMgmt.CreateSession(mySessionToken);
                        string cookieToken = oktaSession.CookieToken;
                        logger.Debug("session Id " + oktaSession.Id + " for User " + userName);
                        string redirectUrl = oktaSessionMgmt.SetSessionCookie(cookieToken, landingPage);
                        return Redirect(redirectUrl);


                    // break;
                    default:
                        logger.Debug("Status: " + myStatus);
                        TempData["errMessage"] = "Status: " + myStatus;
                        break;
                }//end of switch

            }


            if (oidc_but == "Initiate Auth OIDC")
            {
                //version using Custom Authorization Server
                logger.Debug("Initiate OIDC Auth Code without Session");
                Random random = new Random();
                string stateCode = random.Next(99999, 1000000).ToString();
                string oauthUrl = appSettings["oidc.AuthServer"] + "/v1/authorize?response_type=code&response_mode=query&client_id=" + appSettings["oidc.spintweb.clientId"] + "&scope=" + appSettings["oidc.scopes"] + "&state=" + stateCode + "&nonce=CWBb0zHdZ92WqBLkyIuExu&redirect_uri=" + appSettings["oidc.spintweb.RedirectUri"];
                return Redirect(oauthUrl);
            }

            if (oidc_but == "Initiate Implicit OIDC")
            {
                //version using Custom  Authorization Server
                logger.Debug("Initiate OIDC Implicit without Session");
                Random random = new Random();
                string stateCode = random.Next(99999, 1000000).ToString();
                //string stateCode = "myStateInfo";
                string oauthUrl = appSettings["oidc.AuthServer"] + "/v1/authorize?response_type=id_token token&response_mode=form_post&client_id=" + appSettings["oidc.spintnative.clientId"] + "&scope=" + appSettings["oidc.scopes"] + "&state=" + stateCode + "&nonce=CWBb0zHdZ92WqBLkyIuExu&redirect_uri=" + appSettings["oidc.spintnative.RedirectUri"];
                //string oauthUrl = appSettings["oidc.AuthServer"] + "/v1/authorize?response_type=id_token token&response_mode=form_post&client_id=6788997876556&scope=" + appSettings["oidc.scopes"] + "&state=" + stateCode + "&nonce=CWBb0zHdZ92WqBLkyIuExu&redirect_uri=" + appSettings["oidc.spintnative.RedirectUri"];
                return Redirect(oauthUrl);
            }



            if (oidc_but == "Initiate ResourceOwner OIDC")
            {

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
                OidcIdTokenMin oidcIdToken = new OidcIdTokenMin();
                OidcAccessToken oidcAccessToken = new OidcAccessToken();
                string basicAuth = appSettings["oidc.spintnative.clientId"] + ":" + appSettings["oidc.spintnative.clientSecret"];

                var bytesBasicAuth = System.Text.Encoding.UTF8.GetBytes(basicAuth);
                string encodedBasicAuth = System.Convert.ToBase64String(bytesBasicAuth);

                try
                {
                    var client = new RestClient(appSettings["oidc.AuthServer"] + "/v1/token");
                    //var client = new RestClient(MvcApplication.apiUrl + "/oauth2/aus90h4gyj2Hc8QOy0h7/v1/token");
                    var request = new RestRequest(Method.POST);
                    request.AddHeader("Accept", "application/json");
                    request.AddHeader("Content-Type", "application/x-www-form-urlencoded");
                    request.AddHeader("Authorization", " Basic " + encodedBasicAuth);
                    request.AddQueryParameter("grant_type", "password");
                    request.AddQueryParameter("username", userName);
                    request.AddQueryParameter("password", passWord);
                    request.AddQueryParameter("scope", appSettings["oidc.scopes"]);
                    request.AddQueryParameter("redirect_uri", appSettings["oidc.spintnative.RedirectUri"]);
                    response = client.Execute<TokenRequestResponse>(request);
                    error = response.Data.error;
                    error_description = response.Data.error_description;
                    token_type = response.Data.token_type;
                    scope = response.Data.scope;

                    if (response.Data.id_token != null)
                    {
                        idToken = response.Data.id_token;
                        id_token_status = "id_token present";
                        TempData["idToken"] = response.Data.id_token;
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
                            // TempData["errMessage"] = jsonPayload;
                            System.IdentityModel.Tokens.JwtSecurityToken tokenReceived = new System.IdentityModel.Tokens.JwtSecurityToken(idToken);
                            oidcIdToken = Newtonsoft.Json.JsonConvert.DeserializeObject<OidcIdTokenMin>(jsonPayload);
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
                if (accessToken != null || idToken != null)
                {
                    TempData["errMessage"] = "OIDC_Get Oauth Resource Owner SUCCESS token_type = " + token_type + " scope = " + scope + " : " + id_token_status + " : " + access_token_status + " oktaId = " + oidcIdToken.sub;
                    TempData["oktaOrg"] = MvcApplication.apiUrl;
                    //TempData["token"] = MvcApplication.apiToken;

                    return View("../AltLanding/ResOwnerLanding", oidcIdToken);
                }
                else
                {
                    TempData["errMessage"] = "OIDC_Get Oauth Resource Owner error " + error_description;
                    TempData["oktaOrg"] = MvcApplication.apiUrl;
                    //TempData["token"] = MvcApplication.apiToken;
                    return View("../AltLanding/UnprotectedLanding");
                }
 

            }// end handle resource owner workflow



            if (oidc_but == "Client Credential Flow")
            {
                //this is available with Custom Authorization Server
                logger.Debug("Client Credential Flow");
                string error = null;
                string error_description = null;
                string token_type = null;
                string scope = null;
                string access_token_status = null;
                string accessToken = null;
                string id_token_status = null;
                string idToken = null;
                System.IdentityModel.Tokens.JwtSecurityToken tokenReceived2 = null;
                System.IdentityModel.Tokens.JwtSecurityToken tokenReceived3 = null;
                string expires = null;
                IRestResponse<TokenRequestResponse> response = null;
                OidcIdToken oidcIdToken = new OidcIdToken();
                OidcAccessToken oidcAccessToken = new OidcAccessToken();
                string basicAuth = appSettings["oidc.clientcredservice.clientId"] + ":" + appSettings["oidc.clientcredservice.clientSecret"];

                var bytesBasicAuth = System.Text.Encoding.UTF8.GetBytes(basicAuth);
                string encodedBasicAuth = System.Convert.ToBase64String(bytesBasicAuth);


                var client = new RestClient(appSettings["oidc.AuthServer"] + "/v1/token");
                var request = new RestRequest(Method.POST);
                // request.AddHeader("cache-control", "no-cache");
                request.AddHeader("Accept", "application/json");
                request.AddHeader("Content-Type", "application/x-www-form-urlencoded");
                request.AddHeader("Authorization", " Basic " + encodedBasicAuth);
                request.AddQueryParameter("grant_type", "client_credentials");
                request.AddQueryParameter("scope", "clientCred_scope");
                response = client.Execute<TokenRequestResponse>(request);
                //error = response.Data.error;
                //error_description = response.Data.error_description;
                token_type = response.Data.token_type;
                scope = response.Data.scope;
                expires = response.Data.expires_in;

                if (response.Data.access_token != null)
                {
                    accessToken = response.Data.access_token;
                    access_token_status = "access_token present";
                    TempData["accessToken"] = response.Data.access_token;
                    tokenReceived2 = new System.IdentityModel.Tokens.JwtSecurityToken(accessToken);
                }
                else
                {
                    access_token_status = "access_token NOT present";
                }

                if (response.Data.id_token != null)
                {
                    idToken = response.Data.id_token;
                    id_token_status = "id_token present";
                    TempData["idToken"] = response.Data.id_token;
                    tokenReceived3 = new System.IdentityModel.Tokens.JwtSecurityToken(idToken);
                }
                else
                {
                    id_token_status = "id_token NOT present";
                }

                if (accessToken != null )
                {
                    TempData["errMessage"] = "Oauth Client Credentials SUCCESS token_type = " + token_type + " expires " + expires + " scope = " + scope + "  : " + access_token_status;
                    TempData["oktaOrg"] = MvcApplication.apiUrl;
                    //TempData["token"] = MvcApplication.apiToken;
                    //GetInfoResponse getInfoResponse = new GetInfoResponse();
                    return View("../AltLanding/ClientCredLanding");
                }
                else
                {
                    TempData["errMessage"] = "Oauth Client Credentials Error token_type = " + token_type + " expires " + expires + " scope = " + scope + "  : " + access_token_status;
                    TempData["oktaOrg"] = MvcApplication.apiUrl;
                    //TempData["token"] = MvcApplication.apiToken;
                    return View("../AltLanding/UnprotectedLanding");
                }
            }




            TempData["userName"] = userName;
            TempData["passWord"] = passWord;
            //return View("Login");
            return RedirectToAction("UnprotectedLanding", "AltLanding");
        }

    }
}