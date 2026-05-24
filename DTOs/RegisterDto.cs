namespace AuthService.DTOs;

// Til dig der kigger med og tænker
// "Hvorfor har du alt dette med, når brugerdata registreres i UserService?"
// Det er fordi at disse data sendes gennem AuthService
// Så derfor skal vi lige bruge en model til det

public class RegisterDto
{
    public string Email { get; set; } = "";

    public string Password { get; set; } = "";

    public string FirstName { get; set; } = "";

    public string LastName { get; set; } = "";
    public string? PhoneNumber { get; set; }
}