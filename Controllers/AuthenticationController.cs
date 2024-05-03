using AuthenticationAPI.Database;
using AuthenticationAPI.Service;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Swashbuckle.AspNetCore.Annotations;
using System.Security.Cryptography;
using System.Text;
using AuthenticationAPI.Database.Models;
using Microsoft.EntityFrameworkCore;
using MassTransit;
using AuthenticationAPI.MassTransit.Events;
using AuthenticationAPI.Dtos;
using AuthenticationAPI.MassTransit.Responses;

namespace AuthenticationAPI.Controllers
{
    /// <summary>
    /// Authentication Controller
    /// </summary>
    [Route("v1")]
    [ApiController]
    public class AuthenticationController : ControllerBase
    {
        private const string CookieKey = "RefreshToken";

        private static Serilog.ILogger Logger => Serilog.Log.ForContext<AuthenticationController>();
        private readonly AuthenticationApiDbContext _context;
        private readonly JwtService _jwtService;
        private readonly IRequestClient<CreateUserProfileEvent> _clientCreateUserProfile;

        /// <summary>
        /// Constructor of class AuthenticationController
        /// </summary>
        public AuthenticationController(AuthenticationApiDbContext context, JwtService jwtService, IRequestClient<CreateUserProfileEvent> clientCreateUserProfile)
        {
            _context = context;
            _jwtService = jwtService;
            _clientCreateUserProfile = clientCreateUserProfile;
        }

        /// <summary>
        /// Login User
        /// </summary>
        /// <remarks>Login user</remarks>
        /// <param name="loginDto"></param>
        /// <response code="200">Login success</response>
        /// <response code="400">Invalid login or password</response>
        [HttpPost]
        [Route("login")]
        [AllowAnonymous]
        [SwaggerResponse(statusCode: 200, type: typeof(UserDto), description: "Login success")]
        [SwaggerResponse(statusCode: 400, type: typeof(ErrorDto), description: "Invalid email or password")]
        public async Task<IActionResult> PostLogin([FromBody] LoginDto loginDto)
        {
            var user = await _context.Users.FirstOrDefaultAsync(x => x.Email.ToLower() == loginDto.Email.ToLower());
            
            if (user == null || !user.VerifyPasswordHash(loginDto.Password))
                return StatusCode(400, new ErrorDto("Invalid email or password", "400"));

            UserDto dto = new UserDto()
            {
                JwtToken = _jwtService.GenerateAuthorizationToken(user.UserId, user.Role),
                UserId = user.UserId
            };

            var cookieOptions = new CookieOptions
            {
                HttpOnly = true,
                Expires = DateTime.SpecifyKind(DateTime.UtcNow, DateTimeKind.Utc).AddDays(30),
                Secure = true,
                SameSite = SameSiteMode.None
            };

            var refreshToken = _jwtService.GenerateRefreshToken(user.UserId);
            Response.Cookies.Append(CookieKey, refreshToken, cookieOptions);

            return StatusCode(200, dto);
        }

        /// <summary>
        /// Refresh JWT Token
        /// </summary>
        /// <remarks>Refresh JWT token</remarks>
        /// <param name="userDto"></param>
        /// <response code="200">OK</response>
        /// <response code="400">Invalid refresh token</response>
        [HttpPost]
        [Route("refresh")]
        [AllowAnonymous]
        [SwaggerResponse(statusCode: 200, type: typeof(UserDto), description: "OK")]
        [SwaggerResponse(statusCode: 400, type: typeof(ErrorDto), description: "Invalid refresh token")]
        public async Task<IActionResult> PostRefresh([FromBody] UserDto userDto)
        {
            var refreshToken = Request.Cookies[CookieKey];

            if(refreshToken == null)
                return StatusCode(404, new ErrorDto("Invalid refresh token", "404"));

            if (!_jwtService.ValidateRefreshToken(refreshToken, userDto.UserId))
                return StatusCode(400, new ErrorDto("Invalid refresh token", "400"));

            var user = await _context.Users.FirstOrDefaultAsync(x => x.UserId == userDto.UserId);

            if(user == null)
                return StatusCode(400, new ErrorDto("Invalid user data", "400"));

            refreshToken = _jwtService.GenerateRefreshToken(user.UserId);

            var cookieOptions = new CookieOptions
            {
                HttpOnly = true,
                Expires = DateTime.SpecifyKind(DateTime.UtcNow, DateTimeKind.Utc).AddDays(30),
                Secure = true,
                SameSite = SameSiteMode.None
            };

            Response.Cookies.Append(CookieKey, refreshToken, cookieOptions);

            var authorizationToken = _jwtService.GenerateAuthorizationToken(user.UserId, user.Role);

            UserDto dto = new UserDto()
            {
                JwtToken = authorizationToken,
                UserId = user.UserId
            };

            return Ok(dto);
        }

        /// <summary>
        /// Register User
        /// </summary>
        /// <remarks>Register user</remarks>
        /// <param name="registerDto"></param>
        /// <response code="200">Register success</response>
        /// <response code="400">Login already taken</response>
        [HttpPost]
        [Route("register")]
        [AllowAnonymous]
        [SwaggerResponse(statusCode: 200, type: typeof(UserDto), description: "Register success")]
        [SwaggerResponse(statusCode: 400, type: typeof(ErrorDto), description: "Login already taken")]
        public async Task<IActionResult> PostRegister([FromBody] RegisterDto registerDto, CancellationToken cancellationToken)
        {
            var user = _context.Users.FirstOrDefault(x => x.Email.ToLower() == registerDto.Email.ToLower());

            if (user != null)
                return StatusCode(400, new ErrorDto("Email is already taken", "400"));

            var createUserProfileEvent = new CreateUserProfileEvent()
            {
                Name = registerDto.Name,
                Email = registerDto.Email,
            };

            var result = await _clientCreateUserProfile.GetResponse<CreateUserProfileResponse>(createUserProfileEvent, cancellationToken);

            user = new User()
            {
                UserId = result.Message.UserProfileId,
                Email = registerDto.Email.ToLower(),
                Role = "User"
            };

            user.CreatePasswordHash(registerDto.Password);
            _context.Users.Add(user);
            await _context.SaveChangesAsync();


            UserDto dto = new UserDto()
            {
                JwtToken = _jwtService.GenerateAuthorizationToken(user.UserId, "User"),
                UserId = user.UserId
            };

            var cookieOptions = new CookieOptions
            {
                HttpOnly = true,
                Expires = DateTime.SpecifyKind(DateTime.UtcNow, DateTimeKind.Utc).AddDays(30),
                Secure = true,
                SameSite = SameSiteMode.None
            };

            Response.Cookies.Append(CookieKey, dto.JwtToken, cookieOptions);

            return StatusCode(200, dto);
        }

        /// <summary>
        /// Update User Data
        /// </summary>
        /// <remarks>Update user login, password, email</remarks>
        /// <param name="updateUserDto"></param>
        /// <response code="200">OK</response>
        /// <response code="400">Invalid old password</response>
        /// <response code="401">Unauthorized</response>
        [HttpPut]
        [Route("update-user")]
        [Authorize(Roles = "User,Admin")]
        [SwaggerResponse(statusCode: 400, type: typeof(ErrorDto), description: "Invalid old password")]
        public async Task<IActionResult> PutUpdateUser([FromBody] UpdateUserDto updateUserDto)
        {
            var userId = User.Claims.First(x => x.Type == "UserId").Value.ToString();

            var user = _context.Users.FirstOrDefault(x => x.UserId == userId);
            
            if (user == null)
                return StatusCode(404, new ErrorDto("User not found", "404"));

            if (!user.VerifyPasswordHash(updateUserDto.OldPassword))
                return StatusCode(400, new ErrorDto("Invalid old password", "400"));

            if (updateUserDto.Email != user.Email)
            {
                var testUser = await _context.Users.FirstOrDefaultAsync(x => x.Email.ToLower() == updateUserDto.Email.ToLower());

                if (testUser != null)
                    return StatusCode(400, new ErrorDto("Email is already taken", "400"));

                user.Email = updateUserDto.Email;
            }

            if (updateUserDto.NewPassword != null || updateUserDto.NewPassword?.Trim().Length != 0) 
            {
                user.CreatePasswordHash(updateUserDto.NewPassword);
            }
            
            
            await _context.SaveChangesAsync();

            return StatusCode(200);
        }

        /// <summary>
        /// Generate Password Hash
        /// </summary>
        /// <remarks>Generate password hash</remarks>
        /// <param name="password"></param>
        /// <response code="200">OK</response>
        [HttpGet]
        [Route("password")]
        [AllowAnonymous]
        [SwaggerResponse(statusCode: 200, type: typeof(Dictionary<string, string>), description: "OK")]
        public ActionResult<Dictionary<string, string>> GetGeneratePassword(string password)
        {
            Dictionary<string, string> passwordData = new();

            using var hmac = new HMACSHA512();
            passwordData["Salt"] = Convert.ToBase64String(hmac.Key);
            passwordData["Hash"] = Convert.ToBase64String(hmac.ComputeHash(Encoding.UTF8.GetBytes(password)));

            return StatusCode(200, passwordData);
        }
    }
}
