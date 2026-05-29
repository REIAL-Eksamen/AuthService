using MongoDB.Bson;
using MongoDB.Bson.Serialization.Attributes;

//passwordhash så password aldrig gemmes i klartekst. hash og salt bruges til at skjule det. 
//role styrer hva brugere har adgang til og user er sat som standard. 

namespace AuthService.Models;

public class UserModel
{
    [BsonId]
    [BsonRepresentation(BsonType.ObjectId)]
    public string? Id { get; set; }

    public string Email { get; set; } = "";
    public string PasswordHash { get; set; } = "";
    public string Salt { get; set; } = "";
    public string Role { get; set; } = "User";
}