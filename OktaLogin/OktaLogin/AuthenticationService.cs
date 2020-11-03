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
            var authorizeRequestUrl = new RequestUrl($"{AuthConfiguration.OrganizationUrl}/connect/authorize");

            // Dictionary with values for the authorize request
            var dic = new Dictionary<string, string>();
            dic.Add("client_id", AuthConfiguration.ClientId);
            dic.Add("response_type", "code id_token");
            dic.Add("scope", "openid profile email offline_access client-api.full_access");
            dic.Add("redirect_uri", AuthConfiguration.RedirectUri);
            dic.Add("nonce", CreateCryptoGuid());
            dic.Add("code_challenge", CreateCodeChallenge());
            dic.Add("code_challenge_method", "S256");
            dic.Add("state", CreateCryptoGuid());
            dic.Add("acr_values", $"DeviceId:{Guid.NewGuid()}");

            return authorizeRequestUrl.Create(dic);
        }

        public void Logout(string idToken)
        {
            using (HttpClient httpClient = new HttpClient())
            {
                var response = httpClient.PostAsync(BuildLogoutUrl(idToken), null).Result;
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
                HttpResponseMessage response = httpClient.PostAsync($"{AuthConfiguration.OrganizationUrl}/connect/token", content).Result;
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
            return $"{AuthConfiguration.OrganizationUrl}/connect/endsession?id_token_hint={idToken}&post_logout_redirect_uri=zymobile:%2F%2F";
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
