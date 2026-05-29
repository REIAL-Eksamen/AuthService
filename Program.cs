using MassTransit;
using Scalar.AspNetCore;
using System.Text;
using AuthService.Models;
using AuthService.Repositories;
using AuthService.Services;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using VaultSharp;
using VaultSharp.V1.AuthMethods;
using VaultSharp.V1.AuthMethods.Token;

var builder = WebApplication.CreateBuilder(args);

//SSL calidering er slået fra så vi kan snakke med vault lokalt uden et gyldigt certifikat, 
var httpClientHandler = new HttpClientHandler();
httpClientHandler.ServerCertificateCustomValidationCallback =
    (message, cert, chain, sslPolicyErrors) => { return true; };

// FORBINDELSEN TIL VAULT
//henter jwt hemmeligheder fra vault via environment variables. 
//vault_addr og vault_token skal være sat, ellers crasher det hele:(
string vaultUrl = Environment.GetEnvironmentVariable("VAULT_ADDR")
                  ?? throw new Exception("VAULT_ADDR mangler");

string vaultToken = Environment.GetEnvironmentVariable("VAULT_TOKEN")
                    ?? throw new Exception("VAULT_TOKEN mangler");

IAuthMethodInfo authMethod = new TokenAuthMethodInfo(vaultToken);

var vaultClientSettings = new VaultClientSettings(vaultUrl, authMethod)
{
    Namespace = "",
    MyHttpClientProviderFunc = handler
    => new HttpClient(httpClientHandler)
    {
        BaseAddress = new Uri(vaultUrl)
    }
};

IVaultClient vaultClient = new VaultClient(vaultClientSettings);

//henter secret og issuer fra vault, bruges til at signere og validere jwt tokens. 
var secret = await vaultClient.V1.Secrets.KeyValue.V2.
    ReadSecretAsync(path: "jwt", mountPoint: "secret");

string mySecret = secret.Data.Data["Secret"].ToString()!;
string myIssuer = secret.Data.Data["Issuer"].ToString()!;

var jwtSettings = new JwtSettings
{
    Secret = mySecret,
    Issuer = myIssuer
};

builder.Services.AddSingleton(jwtSettings);

builder.Services.AddScoped<AuthService.Services.AuthService>();

builder.Services.AddScoped<IAuthService, AuthService.Services.AuthService>();

builder.Services.AddScoped<IAuthRepository, MongoAuthRepository>();

//sætter RabbitMQ op via masstransit, bruges til at sende events ved bruger oprettelse.
builder.Services.AddMassTransit(x =>
{
    x.UsingRabbitMq((context, cfg) =>
    {
        cfg.Host(builder.Configuration["RabbitMQ:Host"] ?? "rabbitmq", "/", h =>
        {
            h.Username("guest");
            h.Password("guest");
        });
        cfg.ConfigureEndpoints(context);
    });
});

//fortæller applikation at den skal bruge jwt token til at godkende bruger. 
builder.Services
    .AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters()
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            
            ValidIssuer = jwtSettings.Issuer,
            ValidAudience = "FitLifeUsers",
            
            IssuerSigningKey =
                new SymmetricSecurityKey(
                    Encoding.UTF8.GetBytes(jwtSettings.Secret))
        };
    });

// Add services to the container.

builder.Services.AddControllers();
// Learn more about configuring OpenAPI at https://aka.ms/aspnet/openapi
builder.Services.AddOpenApi();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();

    app.MapScalarApiReference();
}

app.UseHttpsRedirection();

app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

app.Run();
