using MongoDB.Driver;
using MongoDB.Bson;
using MongoDB.Bson.Serialization;
using MongoDB.Bson.Serialization.Serializers;
using AuthService.Models;

namespace AuthService.Repositories;

public class MongoAuthRepository : IAuthRepository
{
    // Der fortælles her at der sendes UserModel instanser til DB
    private readonly IMongoCollection<UserModel> _users;

    public MongoAuthRepository(IConfiguration configuration)
    {
        var connectionString = configuration["MongoDB:ConnectionString"];
        var databaseName = configuration["MongoDB:DatabaseName"];
        var collectionName = configuration["MongoDB:CollectionName"];
        
        var client = new MongoClient(connectionString);
        var database = client.GetDatabase(databaseName);
        _users = database.GetCollection<UserModel>(collectionName);
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