using AuthService.Models;

namespace AuthService.Services;

public interface IAuthService
{
    Task<UserModel?> GetByEmailAsync(string email);
    Task CreateUserAsync(UserModel user);
}