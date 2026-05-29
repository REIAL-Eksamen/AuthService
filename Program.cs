using MassTransit;
using Scalar.AspNetCore;
using System.Text;
using AuthService.Models;
using AuthService.Repositories;
using AuthService.Services;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;

var builder = WebApplication.CreateBuilder(args);

var jwtSettings = new JwtSettings
{
    Secret = builder.Configuration["Jwt:Key"]
             ?? throw new Exception("Jwt:Key mangler"),

    Issuer = builder.Configuration["Jwt:Issuer"]
             ?? throw new Exception("Jwt:Issuer mangler")
};

builder.Services.AddSingleton(jwtSettings);

builder.Services.AddScoped<IAuthService, AuthService.Services.AuthService>();
builder.Services.AddScoped<IAuthRepository, MongoAuthRepository>();

builder.Services.AddMassTransit(x =>
{
    x.UsingRabbitMq((context, cfg) =>
    {
        cfg.Host(
            builder.Configuration["RabbitMQ:Host"]!,
            "/",
            h =>
            {
                h.Username(builder.Configuration["RabbitMQ:Username"] ?? "fitlife");
                h.Password(builder.Configuration["RabbitMQ:Password"] ?? "fitlife123");
            });

        cfg.ConfigureEndpoints(context);
    });
});

builder.Services
    .AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
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

builder.Services.AddAuthorization();

builder.Services.AddControllers();
builder.Services.AddOpenApi();

var app = builder.Build();

if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
    app.MapScalarApiReference();
}

// IKKE UseHttpsRedirection() i Azure Container Instance
// app.UseHttpsRedirection();

app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

app.MapGet("/health", () => Results.Ok("OK"));

app.Run();