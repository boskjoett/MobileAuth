using System;
using System.Linq;
using System.IdentityModel.Tokens.Jwt;
using Xamarin.Forms;
using Xamarin.Essentials;

namespace OktaLogin
{
    public partial class MainPage : ContentPage
    {
        private readonly LoginService _loginService;
        private string _idToken;

        public MainPage()
        {
            _loginService = new LoginService();
            InitializeComponent();
        }

        private async void LoginButtonClicked(object sender, EventArgs e)
        {
            try
            {
                var callbackUrl = new Uri(AuthConfiguration.Callback);
                var loginUrl = new Uri(_loginService.BuildAuthenticationUrl());

                WebAuthenticatorResult authenticationResult = await WebAuthenticator.AuthenticateAsync(loginUrl, callbackUrl);
                JwtSecurityToken token = _loginService.ParseAuthenticationResult(authenticationResult);

                _idToken = authenticationResult.IdToken;
                //IdTokenLabel.Text = authenticationResult.IdToken;
                //AccessTokenLabel.Text = authenticationResult.AccessToken;
                ExpiresLabel.Text = token.ValidTo.ToString();

                var nameClaim = token.Claims.FirstOrDefault(claim => claim.Type == "given_name");
                if (nameClaim != null)
                {
                    WelcomeLabel.Text = $"Welcome to Xamarin.Forms {nameClaim.Value}!";
                }
                else
                {
                    WelcomeLabel.Text = $"Welcome to Xamarin.Forms {token.Subject}";
                }

                LogoutButton.IsVisible = !(LoginButton.IsVisible = false);
            }
            catch (Exception ex)
            {
                WelcomeLabel.Text = ex.Message;
            }
        }

        private void LogoutButtonClicked(object sender, EventArgs e)
        {
            WelcomeLabel.Text = "You are logged out";
            IdTokenLabel.Text = "";
            AccessTokenLabel.Text = "";
            ExpiresLabel.Text = "";

            LogoutButton.IsVisible = !(LoginButton.IsVisible = true);

            try
            {
                _loginService.Logout(_idToken);
            }
            catch (Exception ex)
            {
                WelcomeLabel.Text = ex.Message;
            }
        }
    }
}
