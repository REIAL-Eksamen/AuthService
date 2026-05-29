namespace AuthService.Models;


//indeholder de værdier der bruges når vi laver JWT tokens. 
//secret er nøglen der signerer token, den skal holdes hemmelig. 
//issuer er hvem der har udstedt token. 
public class JwtSettings
{
    public string Secret { get; set; } = null!;
    public string Issuer { get; set; } = null!;
}