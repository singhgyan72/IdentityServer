namespace CompanyEmployees.Client.Models
{
    public class AuthenticationSettings
    {
        public bool UseLocalLogin { get; set; }
        public string DefaultScheme { get; set; } = "Cookies";
        public LocalAuthSettings LocalAuth { get; set; } = new();
        public IdentityServerSettings? IdentityServer { get; set; }
    }

    public class LocalAuthSettings
    {
        public string ConnectionString { get; set; } = string.Empty;
        public int LockoutTimeInMinutes { get; set; } = 15;
        public int MaxFailedAttempts { get; set; } = 3;
        public bool RequireConfirmedEmail { get; set; } = true;
        public TokenSettings JwtToken { get; set; } = new();
    }

    public class TokenSettings
    {
        public string Secret { get; set; } = string.Empty;
        public string Issuer { get; set; } = string.Empty;
        public string Audience { get; set; } = string.Empty;
        public int ExpiryInMinutes { get; set; } = 60;
    }

    public class IdentityServerSettings
    {
        public string Authority { get; set; } = string.Empty;
        public string ClientId { get; set; } = string.Empty;
        public string ClientSecret { get; set; } = string.Empty;
    }
}