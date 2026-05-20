using Microsoft.AspNetCore.Authorization;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using AuthService.Models;
using Microsoft.AspNetCore.Mvc;

namespace AuthService.Controllers;

[ApiController]
[Route("[controller]")]
public class AuthController : ControllerBase
{
    
    private readonly IConfiguration _config;
    private readonly ILogger<AuthController> _logger;
    
    public AuthController(ILogger<AuthController> logger, IConfiguration config)
    {
        _config = config;
        _logger = logger;
    }
    
    // Her genereres en JWT token, som bestemmer hvor meget der gives adgang til og hvor længe.
    // Vi har en Issuer som er den der udsteder tokenen.
    // Vores Secret skal være LANG for at virke, denne hashes så med SHA256.
    // Tokenen er knyttet til email'en.
    private string GenerateJwtToken(string email)
    {
        var securityKey =
            new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config["Secret"]));
        var credentials =
            new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);
        var claims = new[]
        {
            new Claim(ClaimTypes.NameIdentifier, email)
        };
        var token = new JwtSecurityToken(
            _config["Issuer"],
            "http://localhost",
            claims,
            expires: DateTime.Now.AddMinutes(15),
            signingCredentials: credentials);
        return new JwtSecurityTokenHandler().WriteToken(token);
    }
    
    // Login endpoint, der tager en email og et password som parametre
    // og sender en token tilbage med adgang til sider der kræver authorisation.
    [AllowAnonymous]
    [HttpPost("login")]
    public async Task<IActionResult> Login([FromBody] LoginModel login)
    {
        // Eksempel på brugerdata
        var users = new List<LoginModel>
        {
            new LoginModel { Email = "test@test.com", Password = "1234" },
            new LoginModel { Email = "user@test.com", Password = "abcd" }
        };
        
        // Her tages brugerinput og der tjekkes om dette passer på de brugere der findes.
        var user = users.FirstOrDefault(u =>
            u.Email == login.Email &&
            u.Password == login.Password);
        
        // Hvis user ikke er null får man en token.
        // Hvis user er null eller forkert får man ikke en token.
        if (user != null)
        {
            var token = GenerateJwtToken(user.Email);
            return Ok(new { token });
        }

        return Unauthorized();
    }
    
    
}