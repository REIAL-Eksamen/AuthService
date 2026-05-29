using AuthService.DTOs;
using AuthService.Models;

//definerer hvad auth skal kunne: registrering, login og bruger oprettelse. 

namespace AuthService.Services;

public interface IAuthService
{
    Task<UserModel?> GetByEmailAsync(string email);
    Task CreateUserAsync(UserModel user);
    Task<string?> LoginAsync(LoginDto login);
    Task<bool> RegisterAsync(CreateUserDto createUser);
}