using CompanyEmployees.Client.Handlers;
using CompanyEmployees.Client.Models;
using Duende.IdentityModel;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using Microsoft.Net.Http.Headers;

namespace CompanyEmployees.Client.Extensions
{
    public static class ServiceExtensions
    {
        public static void ConfigureAuthentication(this IServiceCollection services, IConfiguration configuration)
        {
            //services.Configure<IdentityServerSettings>(configuration.GetSection("IdentityServerSettings"));
            var idpSettings = GetIdentityServerSettings(configuration);
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
                // but we don’t specify that here. That’s because these two scopes are requested by default.

                opt.TokenValidationParameters = new TokenValidationParameters
                {
                    RoleClaimType = JwtClaimTypes.Role
                };

                opt.Scope.Add("offline_access");
            });
        }

        public static void ConfigureIDPClient(this IServiceCollection services, IConfiguration configuration)
        {
            var idpSettings = GetIdentityServerSettings(configuration);
            services.AddHttpClient("IDPClient", client =>
            {
                client.BaseAddress = new Uri(idpSettings.Authority);
                client.DefaultRequestHeaders.Clear();
                client.DefaultRequestHeaders.Add(HeaderNames.Accept, "application/json");
            });
        }

        public static void ConfigureAPIClient(this IServiceCollection services)
        {
            services.AddHttpClient("APIClient", client =>
            {
                client.BaseAddress = new Uri("https://localhost:5001/");
                client.DefaultRequestHeaders.Clear();
                client.DefaultRequestHeaders.Add(HeaderNames.Accept, "application/json");
            }).AddHttpMessageHandler<BearerTokenHandler>(); //Pass the access token in the request header
        }

        public static void ConfigureAuthorizationPolicy(this IServiceCollection services)
        {
            //Authorization policy to allow only authenticated users with the role of Administrator and a claim of country with the value of USA
            services.AddAuthorization(authOpt =>
            {
                authOpt.AddPolicy("CanCreateAndModifyData", policyBuilder =>
                {
                    policyBuilder.RequireAuthenticatedUser();
                    policyBuilder.RequireRole("role", "Administrator");
                    policyBuilder.RequireClaim("country", "USA");
                });
            });
        }

        private static IdentityServerSettings GetIdentityServerSettings(IConfiguration configuration)
        {
            return configuration.GetSection("IdentityServerSettings").Get<IdentityServerSettings>();
        }
    }
}
