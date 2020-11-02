using System;
using System.Linq;
using System.IdentityModel.Tokens.Jwt;
using Xamarin.Forms;
using Xamarin.Essentials;

namespace OktaLogin
{
    public partial class MainPage : ContentPage
    {
        private readonly AuthenticationService _authenticationService;
        private WebAuthenticatorResult _authenticationResult;
        private string _idToken;
        private string _authorizationCode;

        public MainPage()
        {
            _authenticationService = new AuthenticationService();
            InitializeComponent();
        }

        private async void LoginButtonClicked(object sender, EventArgs e)
        {
            try
            {
                var callbackUrl = new Uri(AuthConfiguration.Callback);
                var loginUrl = new Uri(_authenticationService.BuildAuthenticationUrl());

                _authenticationResult = await WebAuthenticator.AuthenticateAsync(loginUrl, callbackUrl);
                JwtSecurityToken token = _authenticationService.ParseAuthenticationResult(_authenticationResult);

                _idToken = _authenticationResult.IdToken;
                _authorizationCode = _authenticationResult?.Properties["code"];

                AccessTokenLabel.Text = _authenticationResult.AccessToken == null ? "AccessToken is null" : "Got AccessToken";
                RefreshTokenLabel.Text = _authenticationResult.RefreshToken == null ? "RefreshToken is null" : "Got RefreshToken";
                ExpiresLabel.Text = $"Valid to {token.ValidTo.ToLocalTime()}";

                var nameClaim = token.Claims.FirstOrDefault(claim => claim.Type == "given_name");
                if (nameClaim != null)
                {
                    StatusLabel.Text = $"You are logged in as {nameClaim.Value}!";
                }
                else
                {
                    StatusLabel.Text = $"You are logged in with user ID {token.Subject}";
                }

                LogoutButton.IsVisible = !(LoginButton.IsVisible = false);
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

            LogoutButton.IsVisible = !(LoginButton.IsVisible = true);

            try
            {
                _authenticationService.Logout(_idToken);

                // Browser.OpenAsync(logoutUri, BrowserLaunchMode.SystemPreferred);
            }
            catch (Exception ex)
            {
                StatusLabel.Text = ex.Message;
            }
        }

        private void GetRefreshTokenButtonClicked(object sender, EventArgs e)
        {
            _authenticationService.GetRefreshToken(_authorizationCode);
        }

        private void CallApiButtonClicked(object sender, EventArgs e)
        {
        }
    }
}
