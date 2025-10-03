using CompanyEmployees.Client.Models;

namespace CompanyEmployees.Client.Services
{
    public interface IAuthenticationService
    {
        Task<AuthenticationResult> LoginAsync(LoginViewModel model);
        Task<AuthenticationResult> RegisterAsync(RegisterViewModel model);
        Task LogoutAsync();
    }
}