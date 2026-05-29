using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using AuthService.DTOs;
using AuthService.Services;

namespace AuthService.Controllers;

[ApiController]
[Route("[controller]")]
public class AuthController : ControllerBase
{
    private readonly IAuthService _db;

    public AuthController(IAuthService db)
    {
        _db = db;
    }

    [HttpPost("login")]
    [AllowAnonymous]
    public async Task<IActionResult> Login([FromBody] LoginDto login)
    {
        var token = await _db.LoginAsync(login);

        if (token == null)
            return Unauthorized();

        return Ok(new LoginResponseDto
        {
            Token = token
        });
    }

    [HttpPost("register")]
    [AllowAnonymous]
    public async Task<IActionResult> Register([FromBody] CreateUserDto createUser)
    {
        var success = await _db.RegisterAsync(createUser);

        if (!success)
            return BadRequest("Brugeren findes allerede.");

        return Ok(new
        {
            message = "Bruger oprettet succesfuldt."
        });
    }
}