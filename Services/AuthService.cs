using AuthService.Models;
using MongoDB.Driver;

namespace AuthService.Services;

public class AuthService : IAuthService
{
    private readonly IMongoCollection<UserModel> _users;

    public AuthService(IConfiguration config)
    {
        var client = new MongoClient(config["MongoDB:ConnectionString"]);
        var db = client.GetDatabase(config["MongoDB:Database"]);
        
        _users = db.GetCollection<UserModel>("UserCollection");
    }


    public async Task<UserModel?> GetByEmailAsync(string email)
    {
        return await _users
            .Find(x => x.Email == email)
            .FirstOrDefaultAsync();
    }


    public async Task CreateUserAsync(UserModel user)
    {
        await _users.InsertOneAsync(user);
    }
}