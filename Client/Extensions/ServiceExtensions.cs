using CompanyEmployees.Client.Data;
using CompanyEmployees.Client.Handlers;
using CompanyEmployees.Client.Models;
using CompanyEmployees.Client.Services;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Net.Http.Headers;

namespace CompanyEmployees.Client.Extensions
{
    public static class ServiceExtensions
    {
        public static void ConfigureHttpClients(this IServiceCollection services, IConfiguration configuration)
        {
            var idpSettings = configuration.GetSection("Authentication:IdentityServer").Get<IdentityServerSettings>(); ;
            services.AddHttpClient("IDPClient", client =>
            {
                client.BaseAddress = new Uri(idpSettings.Authority);
                client.DefaultRequestHeaders.Clear();
                client.DefaultRequestHeaders.Add(HeaderNames.Accept, "application/json");
            });

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

        public static void ConfigureIdentity(this IServiceCollection services, IConfiguration configuration)
        {
            var connectionString = configuration.GetConnectionString("DefaultConnection") ?? 
                throw new InvalidOperationException("Connection string 'DefaultConnection' not found.");

            services.AddDbContext<ApplicationDbContext>(options =>
                options.UseSqlServer(connectionString));

            services.AddIdentity<ApplicationUser, IdentityRole>(options =>
            {
                options.Password.RequiredLength = 8;
                options.Password.RequireDigit = true;
                options.Password.RequireNonAlphanumeric = true;
                options.Password.RequireUppercase = true;
                options.User.RequireUniqueEmail = true;
                options.SignIn.RequireConfirmedEmail = false; // Set to true if email confirmation is implemented
                options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(15);
                options.Lockout.MaxFailedAccessAttempts = 5;
            })
            .AddEntityFrameworkStores<ApplicationDbContext>()
            .AddDefaultTokenProviders();
        }
    }
}
