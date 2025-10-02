using CompanyEmployees.Client.Handlers;
using Duende.IdentityModel;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using Microsoft.Net.Http.Headers;

var builder = WebApplication.CreateBuilder(args);

// Clear the default claim type mappings to ensure that the claims are not altered during token validation.
JsonWebTokenHandler.DefaultInboundClaimTypeMap.Clear();

builder.Services.AddHttpClient("APIClient", client =>
{
    client.BaseAddress = new Uri("https://localhost:5001/");
    client.DefaultRequestHeaders.Clear();
    client.DefaultRequestHeaders.Add(HeaderNames.Accept, "application/json");
}).AddHttpMessageHandler<BearerTokenHandler>(); //Pass the access token in the request header

builder.Services.AddHttpClient("IDPClient", client =>
{
    client.BaseAddress = new Uri("https://localhost:5000/");
    client.DefaultRequestHeaders.Clear();
    client.DefaultRequestHeaders.Add(HeaderNames.Accept, "application/json");
});

//Here, we register authentication as a service and populate the DefaultScheme and DefaultChallengeScheme properties.
//Finally, we call the AddCookie method with the scheme name to register the cookie handler and cookie-based
//authentication for our default scheme. Once the identity token has been validated and transformed into a claims identity,
//it will be stored in a cookie, which can then be used for each request to the web application.
builder.Services.AddAuthentication(opt =>
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
    opt.Authority = "https://localhost:5000";
    opt.ClientId = "companyemployeeclient";
    opt.ResponseType = OpenIdConnectResponseType.Code; //Specifies that we are using the authorization code flow
    opt.SaveTokens = true; //Saves the tokens to the AuthenticationProperties after a successful authorization
    opt.ClientSecret = "CompanyEmployeeClientSecret";
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

builder.Services.AddHttpContextAccessor();
builder.Services.AddTransient<BearerTokenHandler>();

//Authorization policy to allow only authenticated users with the role of Administrator and a claim of country with the value of USA
builder.Services.AddAuthorization(authOpt =>
{
    authOpt.AddPolicy("CanCreateAndModifyData", policyBuilder =>
    {
        policyBuilder.RequireAuthenticatedUser();
        policyBuilder.RequireRole("role", "Administrator");
        policyBuilder.RequireClaim("country", "USA");
    });
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
