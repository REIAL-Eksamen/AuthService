using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using AuthService.DTOs;
using FitLife.Events;
using AuthService.Models;
using AuthService.Repositories;
using MassTransit;
using Microsoft.AspNetCore.Cryptography.KeyDerivation;
using Microsoft.IdentityModel.Tokens;
using MongoDB.Bson;

namespace AuthService.Services;

//the heeart of authservice, det her vores registrering, login og JWT tokens håndteres. 
//passwords hasher vi vi med PBKDF2 og et randomt salt, så de ikke gemmes i klartekst. 
//når bruger registreres, sendes en event videre så andre services kan reagere på det. 

public class AuthService : IAuthService
{
    private readonly IAuthRepository _repository;
    private readonly JwtSettings _jwt;
    private readonly IPublishEndpoint _publishEndpoint;

    public AuthService(
        IAuthRepository repository,
        JwtSettings jwt,
        IPublishEndpoint publishEndpoint)
    {
        _repository = repository;
        _jwt = jwt;
        _publishEndpoint = publishEndpoint;
    }

    public Task<UserModel?> GetByEmailAsync(string email)
    {
        return _repository.GetByEmailAsync(email);
    }

    public Task CreateUserAsync(UserModel user)
    {
        return _repository.CreateUserAsync(user);
    }

    public async Task<string?> LoginAsync(LoginDto login)
    {
        //find brugere, findes den ikke stopper den. 
        var user = await _repository.GetByEmailAsync(login.Email);

        if (user == null)
            return null;

        if (string.IsNullOrWhiteSpace(login.Password))
            return null;
        //hash det indtastede password med det samme salt som da brugeren blev oprettet. 
        var saltBytes = Convert.FromBase64String(user.Salt);

        var hashedInputPassword = Convert.ToBase64String(
            KeyDerivation.Pbkdf2(
                password: login.Password,
                salt: saltBytes,
                prf: KeyDerivationPrf.HMACSHA256,
                iterationCount: 100000,
                numBytesRequested: 256 / 8));

        //matcher det ikke det gemte hash, er passwordet forkert. 
        if (hashedInputPassword != user.PasswordHash)
            return null;

        return GenerateJwtToken(
            user.Id,
            user.Email,
            user.Role ?? "User");
    }

    public async Task<bool> RegisterAsync(CreateUserDto createUser)
    {
        
        //email må ikke være en der er brugt i forvejen. 
        var existingUser =
            await _repository.GetByEmailAsync(createUser.Email);

        if (existingUser != null)
            return false;
        //generer et randomt salt og hash passwordet med det. 
        byte[] saltBytes = new byte[128 / 8];

        using (var rng = RandomNumberGenerator.Create())
        {
            rng.GetNonZeroBytes(saltBytes);
        }

        string salt = Convert.ToBase64String(saltBytes);

        string hashed = Convert.ToBase64String(
            KeyDerivation.Pbkdf2(
                password: createUser.Password,
                salt: Convert.FromBase64String(salt),
                prf: KeyDerivationPrf.HMACSHA256,
                iterationCount: 100000,
                numBytesRequested: 256 / 8));

        var authId = ObjectId.GenerateNewId().ToString();

        var newUser = new UserModel
        {
            Id = authId,
            Email = createUser.Email,
            PasswordHash = hashed,
            Salt = salt,
            Role = "User"
        };

        await _repository.CreateUserAsync(newUser);

        //fortæll resten af systemet at en bruger er blevet oprettet! 
        await _publishEndpoint.Publish(new UserRegisteredEvent
        {
            AuthId = authId,
            Email = createUser.Email,
            FirstName = createUser.FirstName ?? "",
            LastName = createUser.LastName ?? "",
            PhoneNumber = createUser.PhoneNumber,
            Membership = createUser.Membership.ToString(),
            MembershipStatus = createUser.MembershipStatus.ToString()
        });

        return true;
    }
        //laver selve JWT token med brugere id, mail og rolle. 
        //token udløber efter 15min. 
    private string GenerateJwtToken(
        string userId,
        string email,
        string role)
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
            issuer: _jwt.Issuer, 
            audience: "FitLifeUsers",
            claims: claims,
            expires: DateTime.Now.AddMinutes(15),
            signingCredentials: credentials);

        return new JwtSecurityTokenHandler().WriteToken(token);
    }
}