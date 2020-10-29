using System;
using System.Net;
using System.Text;
using System.Security.Cryptography;
using System.IdentityModel.Tokens.Jwt;
using Xamarin.Essentials;

namespace OktaLogin
{
    class LoginService
    {
        private string codeVerifier;
        private const string IDToken = "code%20id_token";
        private const string CodeChallengeMethod = "S256";

        public string BuildAuthenticationUrl()
        {
            var state = CreateCryptoGuid();
            var nonce = CreateCryptoGuid();
            var codeChallenge = CreateCodeChallenge();

            string redirectUri = WebUtility.UrlEncode(OktaConfiguration.Callback);

//            return $"{OktaConfiguration.OrganizationUrl}/oauth2/default/v1/authorize?response_type={IDToken}&scope=openid%20profile&redirect_uri={redirectUri}&client_id={OktaConfiguration.ClientId}&state={state}&code_challenge={codeChallenge}&code_challenge_method={CodeChallengeMethod}&nonce={nonce}";
            return $"{OktaConfiguration.OrganizationUrl}?response_type={IDToken}&scope=openid%20profile%20email&redirect_uri={redirectUri}&client_id={OktaConfiguration.ClientId}&state={state}&code_challenge={codeChallenge}&code_challenge_method={CodeChallengeMethod}&nonce={nonce}";
        }

        public JwtSecurityToken ParseAuthenticationResult(WebAuthenticatorResult authenticationResult)
        {
            var handler = new JwtSecurityTokenHandler();
            var token = handler.ReadJwtToken(authenticationResult.IdToken);
            return token;
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
            codeVerifier = CreateCryptoGuid();
            using (var sha256 = SHA256.Create())
            {
                var codeChallengeBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(codeVerifier));
                return Convert.ToBase64String(codeChallengeBytes);
            }
        }
    }
}
