using AuthService.Models;

namespace AuthService.Repositories;

public interface IAuthRepository
{
    Task<UserModel?> GetByEmailAsync(string email);
    Task CreateUserAsync(UserModel user);
}