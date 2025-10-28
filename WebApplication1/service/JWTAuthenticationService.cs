using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;

namespace WebApplication1.service
{
    public interface IJWTAuthenticationService
    {
        string GenerateToken(string email);
    }

    public class JWTAuthenticationService : IJWTAuthenticationService
    {
        private readonly string _secretKey;
        private readonly string _issuer;
        private readonly string _audience;

        public JWTAuthenticationService(IConfiguration configuration)
        {
            _secretKey = configuration["JwtSettings:SecretKey"]
                         ?? throw new ArgumentNullException("JwtSettings:SecretKey is missing from configuration");
            _issuer = configuration["JwtSettings:Issuer"]
                      ?? throw new ArgumentNullException("JwtSettings:Issuer is missing from configuration");
            _audience = configuration["JwtSettings:Audience"]
                        ?? throw new ArgumentNullException("JwtSettings:Audience is missing from configuration");
        }

        public string GenerateToken(string email)
        {
            var claims = new[]
            {
                new Claim(JwtRegisteredClaimNames.Sub, email),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
            };

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_secretKey));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            var token = new JwtSecurityToken(
                issuer: _issuer,
                audience: _audience,
                claims: claims,
                expires: DateTime.UtcNow.AddHours(1),
                signingCredentials: creds);

            return new JwtSecurityTokenHandler().WriteToken(token);
        }
    }
}
