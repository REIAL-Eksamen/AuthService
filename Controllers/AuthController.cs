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

/*
[ApiController]
[Route("[controller]")]
public class AuthController : ControllerBase
{

    private readonly ILogger<AuthController> _logger;
    private readonly JwtSettings _jwt;
    private readonly IAuthService _db;
    private readonly HttpClient _httpClient;

    public AuthController(
        ILogger<AuthController> logger,
        JwtSettings jwt,
        IAuthService db,
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
    private string GenerateJwtToken(string userId, string email, string role)
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
            new Claim(ClaimTypes.NameIdentifier, userId),
            new Claim(ClaimTypes.Email, email),
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
    [HttpPost("login")]
    [AllowAnonymous]
    public async Task<IActionResult> Login([FromBody] LoginDto login)
    {
        try
        {
            var user = await _db.GetByEmailAsync(login.Email);

            if (user == null) return Unauthorized();
            if (string.IsNullOrWhiteSpace(login.Password)) return Unauthorized();

            var saltBytes = Convert.FromBase64String(user.Salt);

            var hashedInputPassword = Convert.ToBase64String(KeyDerivation.Pbkdf2(
                password: login.Password,
                salt: saltBytes,
                prf: KeyDerivationPrf.HMACSHA256,
                iterationCount: 100000,
                numBytesRequested: 256 / 8));

            if (hashedInputPassword != user.PasswordHash)
                return Unauthorized();

            if (string.IsNullOrWhiteSpace(user.Id))
                return Unauthorized();

            var token = GenerateJwtToken(user.Id, user.Email, user.Role ?? "User");

            return Ok(new LoginResponseDto { Token = token });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "LOGIN FAILED for {Email}", login.Email);
            return StatusCode(500, ex.ToString());
        }
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
*/