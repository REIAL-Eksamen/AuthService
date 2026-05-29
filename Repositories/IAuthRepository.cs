using AuthService.Models;

//definerer hva repo skal kunne, hente bruger på mail og opret en ny bruger. 
namespace AuthService.Repositories;

public interface IAuthRepository
{
    Task<UserModel?> GetByEmailAsync(string email);
    Task CreateUserAsync(UserModel user);
}