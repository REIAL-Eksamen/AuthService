using Microsoft.AspNetCore.Authorization;
using System.Net.Http.Json;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using AuthService.Models;
using Microsoft.AspNetCore.Cryptography.KeyDerivation;
using Microsoft.AspNetCore.Mvc;
using AuthService.DTOs;
using MongoDB.Bson;

namespace AuthService.Controllers;

[ApiController]
[Route("[controller]")]
public class AuthController : ControllerBase
{
    
    private readonly ILogger<AuthController> _logger;
    private readonly JwtSettings _jwt;
    private readonly Services.AuthService _db;
    private readonly HttpClient _httpClient;
    
    public AuthController(
        ILogger<AuthController> logger,
        JwtSettings jwt,
        Services.AuthService db,
        HttpClient httpClient)
    {
        _logger = logger;
        _jwt = jwt;
        _db = db;
        _httpClient = httpClient;
    }
    
    // Her genereres en JWT token, som bestemmer hvor meget der gives adgang til og hvor længe.
    // Vi har en Issuer som er den der udsteder tokenen.
    // Vores Secret skal være LANG for at virke, denne hashes så med SHA256.
    // Tokenen er knyttet til email'en.
    private string GenerateJwtToken(string email, string role)
    {
        var securityKey =
            new SymmetricSecurityKey(
                Encoding.UTF8.GetBytes(_jwt.Secret));
        
        var credentials =
            new SigningCredentials(
                securityKey,
                SecurityAlgorithms.HmacSha256);
        
        var claims = new[]
        {
            new Claim(ClaimTypes.NameIdentifier, email),
            new Claim(ClaimTypes.Role, role)
        };
        
        var token = new JwtSecurityToken(
            _jwt.Issuer,
            "http://localhost",
            claims,
            expires: DateTime.Now.AddMinutes(15),
            signingCredentials: credentials);
        
        return new JwtSecurityTokenHandler().WriteToken(token);
    }
    
    private static List<UserModel> users = new();
    
    // LOGIN
    // Login endpoint, der tager en email og et password som parametre
    // og sender en token tilbage med adgang til sider der kræver authorisation.
    [AllowAnonymous]
    [HttpPost("login")]
    public async Task<IActionResult> Login([FromBody] LoginDto login)
    {
        
        // Her tages brugerinput og der tjekkes om dette passer på de brugere der findes.
        var user = await _db.GetByEmailAsync(login.Email);
        
        // Hvis user er null får man ikke en token.
        if (user == null)
        {
            return Unauthorized();
        }
        
        // Hash det password brugeren skriver
        string hashedInputPassword = Convert.ToBase64String(KeyDerivation.Pbkdf2(
            password: login.Password,
            salt: Convert.FromBase64String(user.Salt),
            prf: KeyDerivationPrf.HMACSHA256,
            iterationCount: 100000,
            numBytesRequested: 256 / 8));

        if (hashedInputPassword != user.PasswordHash)
        {
            return Unauthorized();
        }
        var token = GenerateJwtToken(user.Email, user.Role);

        return Ok(new { token });
    }
    
    // REGISTER
    [AllowAnonymous]
    [HttpPost("register")]
    public async Task<IActionResult> Register([FromBody] CreateUserDto createUser)
    {
        // Tjek om email allerede findes
        var existingUser = await _db.GetByEmailAsync(createUser.Email);

        if (existingUser != null)
        {
            return BadRequest("Brugeren findes allerede.");
        }
        
        // Lav salt
        byte[] saltBytes = new byte[128 / 8];

        using (var rng = RandomNumberGenerator.Create())
        {
            rng.GetNonZeroBytes(saltBytes);
        }

        string salt = Convert.ToBase64String(saltBytes);
        
        // Hash password
        string hashed = Convert.ToBase64String(KeyDerivation.Pbkdf2(
            password: createUser.Password,
            salt: Convert.FromBase64String(salt),
            prf: KeyDerivationPrf.HMACSHA256,
            iterationCount: 100000,
            numBytesRequested: 256 / 8));

        var authId = ObjectId.GenerateNewId().ToString();
        // Gem bruger
        var newUser = new UserModel
        {
            Id = authId,
            Email = createUser.Email,
            PasswordHash = hashed,
            Salt = salt,
            Role = "User"
        };
        
        await _db.CreateUserAsync(newUser);
        
        var createUserDto = new CreateUserDto
        {
            AuthId = authId,
            FirstName = createUser.FirstName,
            LastName = createUser.LastName,
            Email = createUser.Email,
            PhoneNumber = createUser.PhoneNumber,
            Membership = createUser.Membership,
            MembershipStatus = createUser.MembershipStatus
        };
        
        Console.WriteLine(JsonSerializer.Serialize(createUserDto));
        
// DET ER HER DER SKAL RETTES ADDRESSE
        await _httpClient.PostAsJsonAsync(
            "http://user-service:8080/api/users",
            createUserDto
        );

        return Ok(new
        {
            message = "Bruger oprettet succesfuldt."
        });
    }
}