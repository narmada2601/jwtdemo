using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using WebApplication1.Middleware;
using WebApplication1.service;

var builder = WebApplication.CreateBuilder(args);

// Register controllers
builder.Services.AddControllers();

// Register your JWT authentication service

builder.Services.AddSingleton<JWTAuthenticationService>();

// Allow CORS for localhost:4200 Angular app
builder.Services.AddCors(cors =>
{
    cors.AddPolicy("AllowLocalhost4200", policy =>
    {
        policy.WithOrigins("http://localhost:4200")
              .AllowAnyHeader()
              .AllowAnyMethod();
    });
});

var app = builder.Build();
// Enable CORS with the policy
app.UseCors("AllowLocalhost4200");

app.UseMiddleware<CustomJwtMiddleware>();

app.UseAuthorization();

app.MapControllers();// Map controller routes

app.Run();// Run the web app

