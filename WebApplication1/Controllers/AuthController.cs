using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;  // Make sure UserDTO is defined here or import the correct namespace
using WebApplication1.service;

namespace WebApplication1.Controllers
{
    //[Authorize]  // Require authentication for all actions by default
    [Route("api/[controller]")]
    [ApiController]
    //https://localhost:7231/api/Auth/Login
    public class AuthController : ControllerBase
    {
        // Dependencies injected via constructor
        private readonly IAuthenticationService _authenticationService;
        private readonly JWTAuthenticationService _jwtAuthenticationService;

        // Constructor dependency injection for services
        public AuthController(IAuthenticationService authenticationService, JWTAuthenticationService jwtAuthentication)
        {
            _authenticationService = authenticationService;
            _jwtAuthenticationService = jwtAuthentication;
        }
        // POST api/Auth/Login - endpoint for user login

        [HttpPost("Login")]
        public IActionResult Login([FromBody] UserDTO userDTO)
        {
            try
            {

                // Validate the request body is not null
                if (userDTO == null)
                {
                    return BadRequest(new { message = "Request body cannot be null." });
                }
                if (string.IsNullOrEmpty(userDTO.Email))
                {
                    return BadRequest(new { message = "Email is required." });
                }
                if (string.IsNullOrEmpty(userDTO.Password))
                {
                    return BadRequest(new { message = "Password is required." });
                }

                if (userDTO.Email == "test@gmail.com" && userDTO.Password == "123456")
                {
                    string token = _jwtAuthenticationService.GenerateToken(userDTO.Email);
                    return Ok(new { message = "Login successful", token });
                }
                else
                {
                    return Unauthorized(new { message = "Invalid email or password." });
                }
            }
            catch (Exception ex)
            {
                // Log ex here
                return StatusCode(500, new { message = "Internal server error: " + ex.Message });
            }



        }


    }

    // Data transfer object representing the login request payload
    public class UserDTO
    {
        public string? Email { get; set; }
        public string ? Password { get; set; }
    }
}
