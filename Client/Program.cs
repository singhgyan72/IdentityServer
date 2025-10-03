using CompanyEmployees.Client.Extensions;
using CompanyEmployees.Client.Handlers;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.Net.Http.Headers;

var builder = WebApplication.CreateBuilder(args);

// Clear the default claim type mappings to ensure that the claims are not altered during token validation.
JsonWebTokenHandler.DefaultInboundClaimTypeMap.Clear();

builder.Services.ConfigureAPIClient();

builder.Services.ConfigureIDPClient(builder.Configuration);

builder.Services.ConfigureAuthentication(builder.Configuration);

builder.Services.AddHttpContextAccessor();
builder.Services.AddTransient<BearerTokenHandler>();

builder.Services.ConfigureAuthorizationPolicy();

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
