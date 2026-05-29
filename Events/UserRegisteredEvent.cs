namespace FitLife.Events;

public class UserRegisteredEvent
{
    public string AuthId { get; set; } = "";
    public string Email { get; set; } = "";
    public string FirstName { get; set; } = "";
    public string LastName { get; set; } = "";
    public string? PhoneNumber { get; set; }
    public string Membership { get; set; } = "Standard";
    public string MembershipStatus { get; set; } = "Active";
}
