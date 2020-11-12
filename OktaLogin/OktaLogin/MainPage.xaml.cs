using System;
using System.Net.Http;
using System.Linq;
using System.IdentityModel.Tokens.Jwt;
using Xamarin.Forms;
using Xamarin.Essentials;

namespace OktaLogin
{
    public partial class MainPage : ContentPage
    {
        private readonly AuthenticationService _authenticationService;
        private string _idToken;
        private TokenInfo _tokenInfo;

        public MainPage()
        {
            _authenticationService = new AuthenticationService();
            InitializeComponent();
            RefreshTokenButton.IsEnabled = false;
            CallApiButton.IsEnabled = false;
        }

        private async void LoginButtonClicked(object sender, EventArgs e)
        {
            try
            {
                var callbackUrl = new Uri(AuthConfiguration.RedirectUri);
                var loginUrl = new Uri(_authenticationService.BuildAuthorizeRequestUrl());

                WebAuthenticatorResult authenticationResult = await WebAuthenticator.AuthenticateAsync(loginUrl, callbackUrl);
                JwtSecurityToken token = _authenticationService.ParseAuthenticationResult(authenticationResult);

                _idToken = authenticationResult.IdToken;
                string authorizationCode = authenticationResult?.Properties["code"];

                _tokenInfo = _authenticationService.GetTokens(authorizationCode);

                AccessTokenLabel.Text = _tokenInfo.AccessToken == null ? "AccessToken is null" : "Got AccessToken";
                RefreshTokenLabel.Text = _tokenInfo.RefreshToken == null ? "RefreshToken is null" : "Got RefreshToken";
                ExpiresLabel.Text = $"Access token expires at {DateTime.Now.AddSeconds(_tokenInfo.ExpiresIn)}";

                var nameClaim = token.Claims.FirstOrDefault(claim => claim.Type == "given_name");
                if (nameClaim != null)
                {
                    StatusLabel.Text = $"You are logged in as {nameClaim.Value}";
                }
                else
                {
                    var emailClaim = token.Claims.FirstOrDefault(claim => claim.Type == "email");
                    if (emailClaim != null)
                    {
                        StatusLabel.Text = $"You are logged in as {emailClaim.Value}";
                    }
                    else
                    {
                        StatusLabel.Text = $"You are logged in as user ID {token.Subject}";
                    }
                }

                LogoutButton.IsVisible = true;
                RefreshTokenButton.IsEnabled = true;
                CallApiButton.IsEnabled = true;
            }
            catch (Exception ex)
            {
                StatusLabel.Text = ex.Message;
            }
        }

        private void RefreshTokenButtonClicked(object sender, EventArgs e)
        {
            try
            {
                _tokenInfo = _authenticationService.RefreshTokens(_tokenInfo.RefreshToken);

                AccessTokenLabel.Text = _tokenInfo.AccessToken == null ? "AccessToken is null" : "Got AccessToken";
                RefreshTokenLabel.Text = _tokenInfo.RefreshToken == null ? "RefreshToken is null" : "Got RefreshToken";
                ExpiresLabel.Text = $"Access token expires at {DateTime.Now.AddSeconds(_tokenInfo.ExpiresIn)}";
            }
            catch (Exception ex)
            {
                StatusLabel.Text = ex.Message;
            }
        }

        private void LogoutButtonClicked(object sender, EventArgs e)
        {
            StatusLabel.Text = "You are logged out";
            RefreshTokenLabel.Text = "";
            AccessTokenLabel.Text = "";
            ExpiresLabel.Text = "";

            try
            {
                _authenticationService.Logout(_idToken, _tokenInfo.AccessToken, _tokenInfo.RefreshToken);

                LogoutButton.IsVisible = false;
            }
            catch (Exception ex)
            {
                StatusLabel.Text = ex.Message;
            }
        }

        private void CallApiButtonClicked(object sender, EventArgs e)
        {
            using (HttpClient httpClient = _authenticationService.CreateHttpClient(_tokenInfo.AccessToken))
            {
                try
                {
                    string version = httpClient.GetStringAsync($"{AuthConfiguration.OrganizationUrl}/api/client/v1/product/version").Result;
                    StatusLabel.Text = "Version: " + version;
                }
                catch (Exception ex)
                {
                    StatusLabel.Text = ex.Message;
                }
            }
        }
    }
}
