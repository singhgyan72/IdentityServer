namespace CompanyEmployees.Client.Models
{
    public class IdentityServerSettings
    {
        public string Authority { get; set; } = string.Empty;
        public string ClientId { get; set; } = string.Empty;
        public string ClientSecret { get; set; } = string.Empty;
        //public string ResponseType { get; set; } = "code";
        //public bool RequireHttpsMetadata { get; set; } = true;
    }
}