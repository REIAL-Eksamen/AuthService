using MongoDB.Driver;
using MongoDB.Bson;
using MongoDB.Bson.Serialization;
using MongoDB.Bson.Serialization.Serializers;
using AuthService.Models;

//snakker direkte med DB, henter og gemmer bruger i DB. 
//forbindelsen sættes op via vault, så vi ikke har følsomme værdier liggende i kode. 
namespace AuthService.Repositories;

public class MongoAuthRepository : IAuthRepository
{
    //samling af brugere i db. 
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
    
    //finder en bruger på mail, returnerer null hvis ikke findes. 
    public async Task<UserModel?> GetByEmailAsync(string email)
    {
        return await _users
            .Find(x => x.Email == email)
            .FirstOrDefaultAsync();
    }
    //gemmer nu bruger i db. 
    public async Task CreateUserAsync(UserModel user)
    {
        await _users.InsertOneAsync(user);
    }
}