using CompanyEmployees.Client.Extensions;
using CompanyEmployees.Client.Handlers;
using CompanyEmployees.Client.Models;
using Microsoft.AspNetCore.Http;
using Microsoft.IdentityModel.JsonWebTokens;

var builder = WebApplication.CreateBuilder(args);

// Clear the default claim type mappings to ensure that the claims are not altered during token validation.
JsonWebTokenHandler.DefaultInboundClaimTypeMap.Clear();

// Configure services
builder.Services.Configure<AuthenticationSettings>(
    builder.Configuration.GetSection("Authentication"));
    
builder.Services.ConfigureIdentity(builder.Configuration);
builder.Services.ConfigureAuthentication(builder.Configuration);
builder.Services.ConfigureHttpClients(builder.Configuration);
builder.Services.ConfigureAuthorizationPolicy();

builder.Services.AddHttpContextAccessor();
builder.Services.AddTransient<BearerTokenHandler>();

// Configure Anti-forgery
builder.Services.AddAntiforgery(options =>
{
    options.HeaderName = "X-XSRF-TOKEN";
    options.Cookie.Name = "__Host-X-XSRF-TOKEN";
    options.Cookie.SameSite = SameSiteMode.Strict;
    options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
});

builder.Services.AddControllersWithViews();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Home/Error");
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseRouting();

app.UseAuthentication();
app.UseAuthorization();

app.MapStaticAssets();

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}")
    .WithStaticAssets();

app.Run();
