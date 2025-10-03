using Microsoft.AspNetCore.Identity;

namespace CompanyEmployees.IDP.Entities;

public class User : IdentityUser
{
    public string? FirstName { get; set; }
    public string? LastName { get; set; }
    public string? Address { get; set; }
    public string? Country { get; set; }

    //Below properties are to match with LocalAuthentication DB context as we are sharing the same DB
    public string? RefreshToken { get; set; }
    public DateTime? RefreshTokenExpiryTime { get; set; }
}
