using CompanyEmployees.Client.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace CompanyEmployees.Client.Services
{
    public class LocalAuthenticationService : IAuthenticationService
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly IOptions<AuthenticationSettings> _authSettings;
        private readonly IConfiguration _configuration;

        public LocalAuthenticationService(
            UserManager<ApplicationUser> userManager,
            SignInManager<ApplicationUser> signInManager,
            IOptions<AuthenticationSettings> authSettings,
            IConfiguration configuration)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _authSettings = authSettings;
            _configuration = configuration;
        }

        public async Task<AuthenticationResult> LoginAsync(LoginViewModel model)
        {
            var user = await _userManager.FindByNameAsync(model.Username);
            if (user == null)
            {
                return new AuthenticationResult { Succeeded = false, Error = "Invalid username or password" };
            }

            var result = await _signInManager.CheckPasswordSignInAsync(user, model.Password, true);
            if (!result.Succeeded)
            {
                string error = result.IsLockedOut ? "Account is locked out" :
                              result.IsNotAllowed ? "Account is not allowed to sign in" :
                              "Invalid username or password";
                return new AuthenticationResult { Succeeded = false, Error = error };
            }

            var token = await GenerateJwtTokenAsync(user);
            var refreshToken = await GenerateRefreshTokenAsync();

            user.RefreshToken = refreshToken;
            user.RefreshTokenExpiryTime = DateTime.UtcNow.AddDays(7);
            await _userManager.UpdateAsync(user);

            return new AuthenticationResult
            {
                Succeeded = true,
                AccessToken = token,
                RefreshToken = refreshToken
            };
        }

        public async Task<AuthenticationResult> RegisterAsync(RegisterViewModel model)
        {
            var existingUser = await _userManager.FindByNameAsync(model.Username)
                           ?? await _userManager.FindByEmailAsync(model.Email);

            if (existingUser != null)
            {
                return new AuthenticationResult { Succeeded = false, Error = "Username or email already exists" };
            }

            var user = new ApplicationUser
            {
                UserName = model.Username,
                Email = model.Email,
                FirstName = model.FirstName,
                LastName = model.LastName,
                Country = model.Country,
                EmailConfirmed = !_authSettings.Value.LocalAuth.RequireConfirmedEmail
            };

            var result = await _userManager.CreateAsync(user, model.Password);
            if (!result.Succeeded)
            {
                return new AuthenticationResult
                {
                    Succeeded = false,
                    Error = string.Join(", ", result.Errors.Select(e => e.Description))
                };
            }

            await _userManager.AddToRoleAsync(user, "User");
            return new AuthenticationResult { Succeeded = true };
        }

        public async Task LogoutAsync()
        {
            await _signInManager.SignOutAsync();
        }

        private async Task<string> GenerateJwtTokenAsync(ApplicationUser user)
        {
            var roles = await _userManager.GetRolesAsync(user);
            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.Name, user.UserName ?? string.Empty),
                new Claim(ClaimTypes.Email, user.Email ?? string.Empty),
                new Claim(JwtRegisteredClaimNames.Sub, user.Id),
                new Claim("country", user.Country ?? string.Empty),
                new Claim("firstName", user.FirstName ?? string.Empty),
                new Claim("lastName", user.LastName ?? string.Empty)
            };

            foreach (var role in roles)
            {
                claims.Add(new Claim(ClaimTypes.Role, role));
            }

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_authSettings.Value.LocalAuth.JwtToken.Secret));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            var token = new JwtSecurityToken(
                issuer: _authSettings.Value.LocalAuth.JwtToken.Issuer,
                audience: _authSettings.Value.LocalAuth.JwtToken.Audience,
                claims: claims,
                expires: DateTime.UtcNow.AddMinutes(_authSettings.Value.LocalAuth.JwtToken.ExpiryInMinutes),
                signingCredentials: creds
            );

            return new JwtSecurityTokenHandler().WriteToken(token);
        }

        private async Task<string> GenerateRefreshTokenAsync()
        {
            return await Task.Run(() =>
            {
                var randomNumber = new byte[32];
                using var rng = RandomNumberGenerator.Create();
                rng.GetBytes(randomNumber);
                return Convert.ToBase64String(randomNumber);
            });
        }
    }
}