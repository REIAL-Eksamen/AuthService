namespace AuthService.Models;

public class JwtSettings
{
    public string Secret { get; set; } = null!;
    public string Issuer { get; set; } = null!;
}