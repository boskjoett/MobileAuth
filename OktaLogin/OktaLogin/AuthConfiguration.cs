namespace OktaLogin
{
    public class AuthConfiguration
    {
        // Okta 
        //public const string ClientId = "0oagy3fu7HLl8vuYl5d5";
        //public const string OrganizationUrl = "https://dev-5745556.okta.com";
        //public const string AuthorizeEndpointUrl = "https://dev-5745556.okta.com/oauth2/default/v1/authorize";
        //public const string TokenEndpointUrl = "https://dev-5745556.okta.com/oauth2/default/v1/token";
        //public const string RevocationEndpointUrl = "https://dev-5745556.okta.com/oauth2/default/v1/revocation";
        //public const string EndSessionEndpointUrl = "https://dev-5745556.okta.com/oauth2/default/v1/endsession";
        //public const string RedirectUri = "com.okta.dev-5745556:/callback";  // com.okta.dev-5745556://callback
        //public const string CallbackScheme = "com.okta.dev-5745556";
        //public const bool IsOktaLogin = true;

        // Novus
        //public const string ClientId = "mobile";
        //public const string OrganizationUrl = "https://novus.zylinc.cloud/t6n";
        //public const string AuthorizeEndpointUrl = "https://novus.zylinc.cloud/t6n/auth/connect/authorize";
        //public const string TokenEndpointUrl = "https://novus.zylinc.cloud/t6n/auth/connect/token";
        //public const string RevocationEndpointUrl = "https://novus.zylinc.cloud/t6n/auth/connect/revocation";
        //public const string EndSessionEndpointUrl = "https://novus.zylinc.cloud/t6n/auth/connect/endsession";
        //public const string RedirectUri = "zymobile://";
        //public const string CallbackScheme = "zymobile";
        //public const bool IsOktaLogin = false;

        // BCS test server
        public const string ClientId = "mobile";
        public const string OrganizationUrl = "https://novusvm1.westeurope.cloudapp.azure.com";
        public const string AuthorizeEndpointUrl = "https://novusvm1.westeurope.cloudapp.azure.com/connect/authorize";
        public const string TokenEndpointUrl = "https://novusvm1.westeurope.cloudapp.azure.com/connect/token";
        public const string RevocationEndpointUrl = "https://novusvm1.westeurope.cloudapp.azure.com/connect/revocation";
        public const string EndSessionEndpointUrl = "https://novusvm1.westeurope.cloudapp.azure.com/connect/endsession";
        public const string RedirectUri = "zymobile://";
        public const string CallbackScheme = "zymobile";
        public const bool IsOktaLogin = false;
    }
}
