using Android.App;
using Android.Content;
using Android.Content.PM;

namespace OktaLogin.Droid
{
    [Activity(NoHistory = true, LaunchMode = LaunchMode.SingleTop)]
    [IntentFilter(new[] { Intent.ActionView },  Categories = new[] { Intent.CategoryDefault, Intent.CategoryBrowsable }, DataScheme = AuthConfiguration.CallbackScheme)]
    public class WebAuthenticationCallbackActivity : Xamarin.Essentials.WebAuthenticatorCallbackActivity
    {
    }
}