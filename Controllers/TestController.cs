using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

//bare test, bruges til at tjekke jwt og roller virker som de skal. 
namespace AuthService.Controllers;

[ApiController]
[Route("[controller]")]
public class TestController : ControllerBase
{
    [Authorize(Roles = "Admin")]
    [HttpGet("admin")]
    public IActionResult GetAdmin()
    {
        return Ok("You're authorized");
    }
    
    [Authorize(Roles = "User")]
    [HttpGet("user")]
    public IActionResult GetUser()
    {
        return Ok("You're authorized");
    }
}