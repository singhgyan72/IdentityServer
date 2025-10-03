namespace CompanyEmployees.Client.Models
{
    public class AuthenticationResult
    {
        public bool Succeeded { get; set; }
        public string? AccessToken { get; set; }
        public string? RefreshToken { get; set; }
        public string? Error { get; set; }
    }
}