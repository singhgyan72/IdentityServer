using CompanyEmployees.Client.Models;
using CompanyEmployees.Client.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using IAuthService = CompanyEmployees.Client.Services.IAuthenticationService;

namespace CompanyEmployees.Client.Controllers
{
    public class AccountController : Controller
    {
        private readonly IAuthService? _authService;
        private readonly IConfiguration _configuration;

        public AccountController(IConfiguration configuration, IAuthService? authService = null)
        {
            _configuration = configuration;
            _authService = authService;
        }

        [HttpGet]
        public IActionResult Login(string returnUrl = "/")
        {
            // If IDP authentication is enabled, redirect to the IDP login
            var authSettings = _configuration.GetSection("Authentication").Get<AuthenticationSettings>();
            if (authSettings != null && !authSettings.UseLocalLogin)
            {
                return Challenge(new Microsoft.AspNetCore.Authentication.AuthenticationProperties { RedirectUri = returnUrl });
            }

            ViewData["ReturnUrl"] = returnUrl;
            return View();
        }

        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Login(LoginViewModel model, string? returnUrl = null)
        {
            ViewData["ReturnUrl"] = returnUrl;

            // Check if using IDP authentication
            var authSettings = _configuration.GetSection("Authentication").Get<AuthenticationSettings>();
            if (authSettings != null && !authSettings.UseLocalLogin)
            {
                // For IDP, redirect to challenge
                return Challenge(new Microsoft.AspNetCore.Authentication.AuthenticationProperties { RedirectUri = returnUrl ?? "/" });
            }

            if (!ModelState.IsValid)
            {
                return View(model);
            }

            // Only call authentication service for local login
            if (_authService == null)
            {
                ModelState.AddModelError(string.Empty, "Authentication service not available");
                return View(model);
            }

            var result = await _authService.LoginAsync(model);

            if (result.Succeeded)
            {
                // Store tokens in cookies
                if (!string.IsNullOrEmpty(result.AccessToken))
                {
                    HttpContext.Response.Cookies.Append("AccessToken", result.AccessToken, new CookieOptions
                    {
                        HttpOnly = true,
                        Secure = true,
                        SameSite = SameSiteMode.Strict
                    });
                }

                if (!string.IsNullOrEmpty(result.RefreshToken))
                {
                    HttpContext.Response.Cookies.Append("RefreshToken", result.RefreshToken, new CookieOptions
                    {
                        HttpOnly = true,
                        Secure = true,
                        SameSite = SameSiteMode.Strict
                    });
                }

                return RedirectToLocal(returnUrl);
            }

            ModelState.AddModelError(string.Empty, result.Error ?? "Invalid login attempt");
            return View(model);
        }

        [HttpGet]
        [AllowAnonymous]
        public IActionResult Register(string? returnUrl = null)
        {
            var authSettings = _configuration.GetSection("Authentication").Get<AuthenticationSettings>();
            if (authSettings != null && !authSettings.UseLocalLogin)
            {
                return RedirectToAction("Login");
            }

            ViewData["ReturnUrl"] = returnUrl;
            return View();
        }

        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Register(RegisterViewModel model, string? returnUrl = null)
        {
            ViewData["ReturnUrl"] = returnUrl;

            // Check if using IDP authentication
            var authSettings = _configuration.GetSection("Authentication").Get<AuthenticationSettings>();
            if (authSettings != null && !authSettings.UseLocalLogin)
            {
                // For IDP, registration is not handled by the client
                ModelState.AddModelError(string.Empty, "Registration is handled by the Identity Provider.");
                return View(model);
            }

            if (!ModelState.IsValid)
            {
                return View(model);
            }

            // Only call authentication service for local registration
            if (_authService == null)
            {
                ModelState.AddModelError(string.Empty, "Local registration not available");
                return View(model);
            }

            var result = await _authService.RegisterAsync(model);

            if (result.Succeeded)
            {
                // Automatically log in after registration
                var loginResult = await _authService.LoginAsync(new LoginViewModel 
                { 
                    Username = model.Username, 
                    Password = model.Password 
                });

                if (loginResult.Succeeded)
                {
                    return RedirectToLocal(returnUrl);
                }
            }

            ModelState.AddModelError(string.Empty, result.Error ?? "Registration failed");
            return View(model);
        }

        [Authorize]
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Logout()
        {
            var authSettings = _configuration.GetSection("Authentication").Get<AuthenticationSettings>();
            
            if (authSettings != null && !authSettings.UseLocalLogin)
            {
                // IDP logout
                return SignOut(
                    new Microsoft.AspNetCore.Authentication.AuthenticationProperties { RedirectUri = "/" },
                    "Cookies", "OpenIdConnect");
            }
            else
            {
                // Local logout
                // Clear local authentication cookies
                foreach (var cookie in HttpContext.Request.Cookies.Keys)
                {
                    Response.Cookies.Delete(cookie);
                }

                if (_authService != null)
                {
                    await _authService.LogoutAsync();
                }
                return RedirectToAction("Index", "Home");
            }
        }

        private IActionResult RedirectToLocal(string? returnUrl)
        {
            if (!string.IsNullOrEmpty(returnUrl) && Url.IsLocalUrl(returnUrl))
            {
                return Redirect(returnUrl);
            }
            
            return RedirectToAction(nameof(HomeController.Index), "Home");
        }
    }
}