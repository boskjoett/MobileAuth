namespace OktaLogin
{
    public class AuthConfiguration
    {
        // Okta 
        //public const string ClientId = "0oagy3fu7HLl8vuYl5d5";
        //public const string OrganizationUrl = "https://dev-5745556.okta.com";
        //public const string RedirectUri = "com.okta.dev-5745556:/callback";  // com.okta.dev-5745556://callback
        //public const string CallbackScheme = "com.okta.dev-5745556";


        // Novus
        public const string ClientId = "mobile";
        public const string OrganizationUrl = "https://novus.zylinc.cloud/t1n/auth";
        public const string RedirectUri = "zymobile://";
        public const string CallbackScheme = "zymobile";
    }
}
