using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Mvc;  // Make sure UserDTO is defined here or import the correct namespace
using WebApplication1.service;

namespace WebApplication1.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class LoginController : ControllerBase
    {
        private readonly IAuthenticationService _authenticationService;
        private readonly JWTAuthenticationService _jwtAuthenticationService;

        public LoginController(IAuthenticationService authenticationService, JWTAuthenticationService jwtAuthentication)
        {
            _authenticationService = authenticationService;
            _jwtAuthenticationService = jwtAuthentication;
        }

        [HttpPost("LoginUser")]
        public IActionResult LoginUser([FromBody] UserDTO userDTO)
        {
            if (string.IsNullOrEmpty(userDTO.Email) || string.IsNullOrEmpty(userDTO.Password))
            {
                return BadRequest("Kindly don't give your values either null or empty. Please provide the email and password correctly");
            }

            // Demo hardcoded user check, replace with real logic for actual authentication
            if (userDTO.Email == "test@example.com" && userDTO.Password == "123456")
            {
                string token = _jwtAuthenticationService.GenerateToken(userDTO.Email);
                return Ok(new { Token = token });
            }
            else
            {
                return Unauthorized("Invalid Email and password");
            }
        }

        [HttpGet("Test")]
        public IActionResult Test()
        {
            return Ok(new { Token = "testing token" });
        }
    }

    // Example UserDTO
    public class UserDTO
    {
        public string? Email { get; set; }
        public string ? Password { get; set; }
    }
}
