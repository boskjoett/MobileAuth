namespace OktaLogin
{
    public class OktaConfiguration
    {
        // Okta 
        //public const string ClientId = "0oagy3fu7HLl8vuYl5d5";
        //public const string OrganizationUrl = "https://dev-5745556.okta.com";
        //public const string Callback = "com.okta.dev-5745556:/callback";  // com.okta.dev-5745556://callback
        //public const string CallbackScheme = "com.okta.dev-5745556";


        // Novus
        public const string ClientId = "xamarin";
//        public const string OrganizationUrl = "https://novus.zylinc.cloud/t6n/auth/mobileauth/idsrv";
        public const string OrganizationUrl = "https://novus.zylinc.cloud/t6n/auth/connect/authorize";
        public const string Callback = "xamarinessentials://";
        public const string CallbackScheme = "xamarinessentials";
    }
}
