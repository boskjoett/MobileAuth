using System;
using System.Text;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.IdentityModel.Tokens.Jwt;
using Xamarin.Essentials;
using IdentityModel;
using IdentityModel.Client;
using Newtonsoft.Json;

namespace OktaLogin
{
    class AuthenticationService
    {
        private string _codeVerifier;

        public string BuildAuthorizeRequestUrl()
        {
            var authorizeRequestUrl = new RequestUrl(AuthConfiguration.AuthorizeEndpointUrl);

            // Dictionary with values for the authorize request
            var dic = new Dictionary<string, string>();
            dic.Add("client_id", AuthConfiguration.ClientId);
            dic.Add("response_type", "code id_token");
//            dic.Add("scope", "openid profile email offline_access");  // For Okta
            dic.Add("scope", "openid profile email offline_access client-api.full_access");  // For Novus
            dic.Add("redirect_uri", AuthConfiguration.RedirectUri);
            dic.Add("nonce", CreateCryptoGuid());
            dic.Add("code_challenge", CreateCodeChallenge());
            dic.Add("code_challenge_method", "S256");
            dic.Add("state", CreateCryptoGuid());
            dic.Add("acr_values", $"DeviceId:{Guid.NewGuid()}");

            return authorizeRequestUrl.Create(dic);

            //string state = CreateCryptoGuid();
            //string nonce = CreateCryptoGuid();
            //string codeChallenge = CreateCodeChallenge();
            //string redirectUri = WebUtility.UrlEncode(AuthConfiguration.RedirectUri);

            //return $"{AuthConfiguration.OrganizationUrl}/connect/authorize?response_type=code%20id_token&scope=openid%20profile%20email%20offline_access%20client-api.full_access&redirect_uri={redirectUri}&client_id={AuthConfiguration.ClientId}&state={state}&code_challenge={codeChallenge}&code_challenge_method=S256&nonce={nonce}";
        }

        public void Logout(string idToken, string refreshToken)
        {
            using (HttpClient httpClient = new HttpClient())
            {
                // Call endsession endpoint
                HttpResponseMessage response = httpClient.GetAsync($"{AuthConfiguration.EndSessionEndpointUrl}?id_token_hint={idToken}&post_logout_redirect_uri=zymobile%3A%2F%2F").Result;

                // Call token revocation endpoint
                var content = new StringContent($"token={refreshToken}&token_type_hint=refresh_token&client_id={AuthConfiguration.ClientId}");
                content.Headers.ContentType = new MediaTypeHeaderValue("application/x-www-form-urlencoded");
                response = httpClient.PostAsync($"{AuthConfiguration.RevocationEndpointUrl}", content).Result;

                // Call SignOutAsync endpoint
                response = httpClient.PostAsync($"{AuthConfiguration.OrganizationUrl}/Account/signout", null).Result;
            }
        }

        /// <summary>
        /// Calls the authentication service's token endpoint to get access token and refresh token.
        /// </summary>
        /// <param name="authorizationCode">Authorization code</param>
        /// <returns>Token info</returns>
        public TokenInfo GetTokens(string authorizationCode)
        {
            using (HttpClient httpClient = new HttpClient())
            {
                string redirectUri = WebUtility.UrlEncode(AuthConfiguration.RedirectUri);
                var content = new StringContent($"grant_type=authorization_code&client_id={AuthConfiguration.ClientId}&code={authorizationCode}&redirect_uri={redirectUri}&code_verifier={_codeVerifier}");
                content.Headers.ContentType = new MediaTypeHeaderValue("application/x-www-form-urlencoded");
                HttpResponseMessage response = httpClient.PostAsync($"{AuthConfiguration.TokenEndpointUrl}", content).Result;
                string responseBody = response.Content.ReadAsStringAsync().Result;
                TokenInfo userToken = JsonConvert.DeserializeObject<TokenInfo>(responseBody);
                return userToken;
            }
        }

        /// <summary>
        /// Calls the authentication service's token endpoint to renew the access token using a refresh token.
        /// </summary>
        /// <param name="refreshToken">Refresh token</param>
        /// <returns>Token info</returns>
        public TokenInfo RefreshTokens(string refreshToken)
        {
            using (HttpClient httpClient = new HttpClient())
            {
                string redirectUri = WebUtility.UrlEncode(AuthConfiguration.RedirectUri);
                var content = new StringContent($"grant_type=refresh_token&client_id={AuthConfiguration.ClientId}&refresh_token={refreshToken}");
                content.Headers.ContentType = new MediaTypeHeaderValue("application/x-www-form-urlencoded");
                HttpResponseMessage response = httpClient.PostAsync($"{AuthConfiguration.TokenEndpointUrl}", content).Result;
                string responseBody = response.Content.ReadAsStringAsync().Result;
                TokenInfo userToken = JsonConvert.DeserializeObject<TokenInfo>(responseBody);
                return userToken;
            }
        }

        public JwtSecurityToken ParseAuthenticationResult(WebAuthenticatorResult authenticationResult)
        {
            var handler = new JwtSecurityTokenHandler();
            var token = handler.ReadJwtToken(authenticationResult.IdToken);
            return token;
        }

        public HttpClient CreateHttpClient(string accessToken = null)
        {
            var client = new HttpClient();
            client.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

            if (!string.IsNullOrEmpty(accessToken))
            {
                client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
            }

            return client;
        }

        private string BuildLogoutUrl(string idToken)
        {
            return $"{AuthConfiguration.EndSessionEndpointUrl}?id_token_hint={idToken}&post_logout_redirect_uri=zymobile%3A%2F%2F";
        }

        private string CreateCryptoGuid()
        {
            using (var generator = RandomNumberGenerator.Create())
            {
                var bytes = new byte[16];
                generator.GetBytes(bytes);
                return new Guid(bytes).ToString("N");
            }
        }

        private string CreateCodeChallenge()
        {
            string codeChallenge;

            _codeVerifier = CryptoRandom.CreateUniqueId();
            using (var sha256 = SHA256.Create())
            {
                var challengeBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(_codeVerifier));
                codeChallenge = Base64Url.Encode(challengeBytes);
            }

            return codeChallenge;
        }
    }
}
