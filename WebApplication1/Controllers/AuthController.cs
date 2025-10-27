using Microsoft.AspNetCore.Mvc;
using WebApplication1.model;   // Namespace for User model
using WebApplication1.service; // Namespace for JwtTokenService

namespace WebApplication1.Controllers
{
    [Route("api/[controller]")]  // Route attribute sets base URL to api/auth
    [ApiController]              // Marks this class as an API controller
    public class AuthController : ControllerBase
    {
        private readonly IJwtTokenService _jwtTokenService;

        // Constructor injection of JwtTokenService interface
        public AuthController(IJwtTokenService jwtTokenService)
        {
            _jwtTokenService = jwtTokenService;
        }

        //https://localhost:5059/api/auth/login
        // Defines POST method accessible via api/auth/login
        [HttpPost("login")]
        public IActionResult Login([FromBody] User login)
        {
            // Write login attempt to console
            Console.WriteLine($"User login attempt - Email: '{login.Email}', Password: '{login.Password}'");

            // Hardcoded demo user for authentication check
            var demoUser = new User
            {
                Id = Guid.NewGuid(),          // Assign new GUID
                Email = "test@gmail.com",     // Hardcoded email
                Password = "123456"           // Hardcoded password
            };

            // Compare input user email and password with demoUser
            if (login.Email?.Trim().ToLower() == demoUser.Email.ToLower() &&
                login.Password?.Trim() == demoUser.Password)
            {
                // Credentials valid, generate JWT token
                var token = _jwtTokenService.GenerateToken(demoUser);

                // Return success response with token
                return Ok(new { token, message = "Login successful!" });
            }

            // Credentials invalid, return 401 Unauthorized with message
            return Unauthorized(new { message = "Invalid credentials" });
        }
    }
}
