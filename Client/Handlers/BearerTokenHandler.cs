using CompanyEmployees.Client.Models;
using Duende.IdentityModel.Client;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using System.Globalization;
using System.IdentityModel.Tokens.Jwt;

namespace CompanyEmployees.Client.Handlers;

public class BearerTokenHandler : DelegatingHandler
{
    private readonly IHttpContextAccessor _httpContextAccessor;
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly IOptions<AuthenticationSettings> _authSettings;

    public BearerTokenHandler(IHttpContextAccessor httpContextAccessor, IHttpClientFactory httpClientFactory, IOptions<AuthenticationSettings> authSettings)
    {
        _httpContextAccessor = httpContextAccessor;
        _httpClientFactory = httpClientFactory;
        _authSettings = authSettings;
    }

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var accessToken = await GetAccessTokenAsync();

        if (!string.IsNullOrWhiteSpace(accessToken))
            request.SetBearerToken(accessToken);

        return await base.SendAsync(request, cancellationToken);
    }

    public async Task<string?> GetAccessTokenAsync()
    {
        if (_httpContextAccessor.HttpContext == null)
            return null;

        // Check if using local authentication
        if (_authSettings.Value.UseLocalLogin)
        {
            // For local authentication, get token from cookies
            if (_httpContextAccessor.HttpContext.Request.Cookies.TryGetValue("AccessToken", out var localToken))
            {
                // Validate that the token is not expired
                if (!string.IsNullOrEmpty(localToken) && IsTokenValid(localToken))
                {
                    return localToken;
                }
                else
                {
                    // Token is expired or invalid, try to refresh it
                    var refreshedToken = await RefreshLocalTokenAsync();
                    if (!string.IsNullOrEmpty(refreshedToken))
                    {
                        // Update the cookie with the new token
                        _httpContextAccessor.HttpContext.Response.Cookies.Append("AccessToken", refreshedToken, new CookieOptions
                        {
                            HttpOnly = true,
                            Secure = true,
                            SameSite = SameSiteMode.Strict
                        });
                        return refreshedToken;
                    }
                }
            }
            return null;
        }

        // For IDP authentication, use the existing logic
        var expiresAtToken = await _httpContextAccessor.HttpContext.GetTokenAsync("expires_at");
        if (string.IsNullOrEmpty(expiresAtToken))
            return null;

        var expiresAtDateTimeOffset = DateTimeOffset.Parse(expiresAtToken, CultureInfo.InvariantCulture);

        if ((expiresAtDateTimeOffset.AddSeconds(-60)).ToUniversalTime() > DateTime.UtcNow)
        {
            return await _httpContextAccessor.HttpContext.GetTokenAsync(OpenIdConnectParameterNames.AccessToken);
        }

        var refreshResponse = await GetRefreshResponseFromIDP();
        if (refreshResponse == null || string.IsNullOrEmpty(refreshResponse.AccessToken))
            return null;

        var updatedTokens = GetUpdatedTokens(refreshResponse);

        var currentAuthenticateResult = await _httpContextAccessor.HttpContext.AuthenticateAsync(CookieAuthenticationDefaults.AuthenticationScheme);
        if (currentAuthenticateResult?.Properties != null && currentAuthenticateResult.Principal != null)
        {
            currentAuthenticateResult.Properties.StoreTokens(updatedTokens);

            await _httpContextAccessor.HttpContext.SignInAsync(
                CookieAuthenticationDefaults.AuthenticationScheme,
                currentAuthenticateResult.Principal,
                currentAuthenticateResult.Properties);
        }

        return refreshResponse.AccessToken;
    }

    private async Task<TokenResponse?> GetRefreshResponseFromIDP()
    {
        if (_httpContextAccessor.HttpContext == null)
            return null;

        var idpClient = _httpClientFactory.CreateClient("IDPClient");
        var metaDataResponse = await idpClient.GetDiscoveryDocumentAsync();

        if (metaDataResponse.IsError)
            return null;

        var refreshToken = await _httpContextAccessor.HttpContext.GetTokenAsync(OpenIdConnectParameterNames.RefreshToken);
        if (string.IsNullOrEmpty(refreshToken))
            return null;

        var refreshResponse = await idpClient.RequestRefreshTokenAsync(
            new RefreshTokenRequest
            {
                Address = metaDataResponse.TokenEndpoint,
                ClientId = "companyemployeeclient",
                ClientSecret = "CompanyEmployeeClientSecret",
                RefreshToken = refreshToken
            });

        return refreshResponse;
    }

    private List<AuthenticationToken> GetUpdatedTokens(TokenResponse refreshResponse)
    {
        var updatedTokens = new List<AuthenticationToken>
        {
            new AuthenticationToken
            {
                Name = OpenIdConnectParameterNames.IdToken,
                Value = refreshResponse.IdentityToken ?? string.Empty
            },
            new AuthenticationToken
            {
                Name = OpenIdConnectParameterNames.AccessToken,
                Value = refreshResponse.AccessToken ?? string.Empty
            },
            new AuthenticationToken
            {
                Name = OpenIdConnectParameterNames.RefreshToken,
                Value = refreshResponse.RefreshToken ?? string.Empty
            },
            new AuthenticationToken
            {
                Name = "expires_at",
                Value = (DateTime.UtcNow + TimeSpan.FromSeconds(refreshResponse.ExpiresIn)).
                    ToString("o", CultureInfo.InvariantCulture)
            }
        };

        return updatedTokens;
    }

    private bool IsTokenValid(string token)
    {
        try
        {
            var handler = new JwtSecurityTokenHandler();
            if (!handler.CanReadToken(token))
                return false;

            var jwtToken = handler.ReadJwtToken(token);
            return jwtToken.ValidTo > DateTime.UtcNow.AddMinutes(5); // Token should be valid for at least 5 more minutes
        }
        catch
        {
            return false;
        }
    }

    private Task<string?> RefreshLocalTokenAsync()
    {
        if (_httpContextAccessor.HttpContext == null)
            return Task.FromResult<string?>(null);

        // Get refresh token from cookies
        if (!_httpContextAccessor.HttpContext.Request.Cookies.TryGetValue("RefreshToken", out var refreshToken))
            return Task.FromResult<string?>(null);

        // For local authentication, we would need to call a refresh endpoint
        // For now, we'll return null as local token refresh would require additional implementation
        // In a production scenario, you'd implement a token refresh endpoint in your local auth service
        
        return Task.FromResult<string?>(null); // TODO: Implement local token refresh if needed
    }
}
