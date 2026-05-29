namespace FitLife.Events;

//en evenet der fyres af når bruger opretter sig. 
//bruges til at fortælle resten af systemet at der er en ny bruger. 
//så andre servics kan oprette deres egne "repræsentation" af brugeren. 
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
