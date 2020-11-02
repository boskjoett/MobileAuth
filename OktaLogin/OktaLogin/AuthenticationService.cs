using System;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Security.Cryptography;
using System.IdentityModel.Tokens.Jwt;
using Xamarin.Essentials;
using IdentityModel;

namespace OktaLogin
{
    class AuthenticationService
    {
        private const string IDToken = "code%20id_token%20token";
        private const string CodeChallengeMethod = "S256";
        private string _codeVerifier;

        public string BuildAuthenticationUrl()
        {
            string state = CreateCryptoGuid();
            string nonce = CreateCryptoGuid();
            string codeChallenge = CreateCodeChallenge();
            
            //string codeChallenge = WebUtility.UrlEncode(CreateCodeChallenge());

            string redirectUri = WebUtility.UrlEncode(AuthConfiguration.Callback);

            // return $"{OktaConfiguration.OrganizationUrl}/oauth2/default/v1/authorize?response_type={IDToken}&scope=openid%20profile&redirect_uri={redirectUri}&client_id={OktaConfiguration.ClientId}&state={state}&code_challenge={codeChallenge}&code_challenge_method={CodeChallengeMethod}&nonce={nonce}";
            return $"{AuthConfiguration.OrganizationUrl}/connect/authorize?response_type={IDToken}&scope=openid%20profile%20email%20offline_access&redirect_uri={redirectUri}&client_id={AuthConfiguration.ClientId}&state={state}&code_challenge={codeChallenge}&code_challenge_method={CodeChallengeMethod}&nonce={nonce}";
        }

        public void Logout(string idToken)
        {
            using (HttpClient httpClient = new HttpClient())
            {
                var response = httpClient.PostAsync(BuildLogoutUrl(idToken), null).Result;
            }
        }

        public string GetRefreshToken(string authorizationCode)
        {
            using (HttpClient httpClient = new HttpClient())
            {
                string redirectUri = WebUtility.UrlEncode(AuthConfiguration.Callback);
                var content = new StringContent($"grant_type=authorization_code&client_id={AuthConfiguration.ClientId}&code={authorizationCode}&redirect_uri={redirectUri}&code_verifier={_codeVerifier}");
                content.Headers.ContentType = new MediaTypeHeaderValue("application/x-www-form-urlencoded");
                HttpResponseMessage response = httpClient.PostAsync($"{AuthConfiguration.OrganizationUrl}/connect/token", content).Result;
                var statusCode = response.StatusCode;
                return "";
            }
        }

        public JwtSecurityToken ParseAuthenticationResult(WebAuthenticatorResult authenticationResult)
        {
            var handler = new JwtSecurityTokenHandler();
            var token = handler.ReadJwtToken(authenticationResult.IdToken);
            return token;
        }

        HttpClient CreateHttpClient(string token = null)
        {
            var client = new HttpClient();
            client.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

            if (!string.IsNullOrEmpty(token))
            {
                client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
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
