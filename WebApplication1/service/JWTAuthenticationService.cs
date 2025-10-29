using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
/*The service reads JWT settings (SecretKey, Issuer, Audience) from config.

It creates a token with subject and JTI claims.

Signs the token using HMAC SHA256 with your secret key.

Sets token expiration to 1 hour.

Returns the serialized JWT string for client usage (e.g., in HTTP Authorization header). */
namespace WebApplication1.service
{
    public interface IJWTAuthenticationService
    {
        string GenerateToken(string email);
    }
    // Implementation of JWT token generation service
    public class JWTAuthenticationService : IJWTAuthenticationService
    {
        private readonly string _secretKey;
        private readonly string _issuer;
        private readonly string _audience;
        // Constructor reads required JwtSettings keys from configuration
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
                new Claim(JwtRegisteredClaimNames.Sub, email),//// Subject claim - typically the username/email of the user
                // JTI claim - a unique ID for the token to prevent replay attacks
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

            return new JwtSecurityTokenHandler().WriteToken(token);/// Serialize the token to a compact string format (base64 encoded)
        }
    }
}
