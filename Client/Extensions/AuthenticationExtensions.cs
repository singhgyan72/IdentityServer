using CompanyEmployees.Client.Models;
using CompanyEmployees.Client.Services;
using Duende.IdentityModel;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using System.Text;

namespace CompanyEmployees.Client.Extensions
{
    public static class AuthenticationExtensions
    {
        public static void ConfigureAuthentication(this IServiceCollection services, IConfiguration configuration)
        {
            var authSettings = configuration.GetSection("Authentication").Get<AuthenticationSettings>();

            if (authSettings == null)
                throw new InvalidOperationException("Authentication settings are not configured.");

            if (authSettings.UseLocalLogin)
            {
                ConfigureLocalAuthentication(services, authSettings.LocalAuth);
                // Only register LocalAuthenticationService when using local authentication
                services.AddScoped<Services.IAuthenticationService, LocalAuthenticationService>();
            }
            else
            {
                if (authSettings.IdentityServer == null)
                    throw new InvalidOperationException("IdentityServer settings are not configured.");
                    
                ConfigureIDPAuthentication(services, authSettings.IdentityServer);
                // For IDP authentication, we don't need a custom authentication service
                // The built-in OpenIdConnect middleware handles authentication
            }
        }

        private static void ConfigureLocalAuthentication(IServiceCollection services, LocalAuthSettings authSettings)
        {
            //var jwtSettings = configuration.GetSection("JwtSettings");
            var secretKey = Encoding.UTF8.GetBytes(authSettings.JwtToken.Secret ??
                throw new InvalidOperationException("JWT Secret Key is not configured."));

            services.AddAuthentication(options =>
            {
                options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                options.DefaultSignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                options.DefaultChallengeScheme = CookieAuthenticationDefaults.AuthenticationScheme;
            })
            .AddCookie(CookieAuthenticationDefaults.AuthenticationScheme, options =>
            {
                options.LoginPath = "/Account/Login";
                options.LogoutPath = "/Account/Logout";
                options.AccessDeniedPath = "/Account/AccessDenied";
                options.SlidingExpiration = true;
                options.ExpireTimeSpan = TimeSpan.FromMinutes(60);
            })
            .AddJwtBearer(JwtBearerDefaults.AuthenticationScheme, options =>
            {
                options.TokenValidationParameters = new TokenValidationParameters
                {
                    ValidateIssuer = true,
                    ValidateAudience = true,
                    ValidateLifetime = true,
                    ValidateIssuerSigningKey = true,
                    ValidIssuer = authSettings.JwtToken.Issuer,
                    ValidAudience = authSettings.JwtToken.Audience,
                    IssuerSigningKey = new SymmetricSecurityKey(secretKey)
                };
            });
        }

        private static void ConfigureIDPAuthentication(IServiceCollection services, IdentityServerSettings idpSettings)
        {
            //services.Configure<IdentityServerSettings>(configuration.GetSection("IdentityServerSettings"));
            if (string.IsNullOrEmpty(idpSettings?.ClientId))
            {
                throw new InvalidOperationException("IdentityServer ClientId is not configured.");
            }

            //Here, we register authentication as a service and populate the DefaultScheme and DefaultChallengeScheme properties.
            //Finally, we call the AddCookie method with the scheme name to register the cookie handler and cookie-based
            //authentication for our default scheme. Once the identity token has been validated and transformed into a claims identity,
            //it will be stored in a cookie, which can then be used for each request to the web application.
            services.AddAuthentication(opt =>
            {
                opt.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                opt.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
            }).AddCookie(CookieAuthenticationDefaults.AuthenticationScheme, opt =>
            {
                opt.AccessDeniedPath = "/Auth/AccessDenied";
            })
            //Add the OpenID Connect handler and configure it to use the authority of our identity server.
            .AddOpenIdConnect(OpenIdConnectDefaults.AuthenticationScheme, opt =>
            {
                opt.SignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                opt.Authority = idpSettings.Authority;
                opt.ClientId = idpSettings.ClientId;
                opt.ResponseType = OpenIdConnectResponseType.Code; //idpSettings.ResponseType;
                opt.SaveTokens = true; //Saves the tokens to the AuthenticationProperties after a successful authorization
                opt.ClientSecret = idpSettings.ClientSecret;
                opt.RequireHttpsMetadata = true; //idpSettings.RequireHttpsMetadata;
                opt.GetClaimsFromUserInfoEndpoint = true;
                opt.ClaimActions.DeleteClaim("sid");
                opt.ClaimActions.DeleteClaim("idp");
                opt.Scope.Add("address");
                opt.Scope.Add("roles");
                opt.ClaimActions.MapUniqueJsonKey("role", "role");
                opt.Scope.Add("companyemployeeapi.scope");
                opt.Scope.Add("country");
                opt.ClaimActions.MapUniqueJsonKey("country", "country");
                // In the IDP Config class, we have defined the OpenId and the Profile scopes as the AllowedScopes (Client configuration part),
                // but we don�t specify that here. That�s because these two scopes are requested by default.

                opt.TokenValidationParameters = new TokenValidationParameters
                {
                    RoleClaimType = JwtClaimTypes.Role
                };

                opt.Scope.Add("offline_access");
            });
        }
    }
}