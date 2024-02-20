using AuthenticationAPI.Database;
using AuthenticationAPI.Models;
using AuthenticationAPI.Service;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Swashbuckle.AspNetCore.Annotations;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Cryptography;
using System.Text;
using System.Linq;
using AuthenticationAPI.Database.Models;
using Serilog;

namespace AuthenticationAPI.Controllers
{
    /// <summary>
    /// Authentication Controller
    /// </summary>
    [Route("/api/authentication-api/v1")]
    [ApiController]
    public class AuthenticationController : ControllerBase
    {
        private const string CookieKey = "RefreshToken";

        private static Serilog.ILogger Logger => Serilog.Log.ForContext<AuthenticationController>();
        private readonly AuthenticationApiDbContext _context;
        private readonly JwtService _jwtService;

        /// <summary>
        /// Constructor of class AuthenticationController
        /// </summary>
        public AuthenticationController(AuthenticationApiDbContext context, JwtService jwtService)
        {
            _context = context;
            _jwtService = jwtService;
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
        [SwaggerResponse(statusCode: 400, type: typeof(ErrorDto), description: "Invalid login or password")]
        public async Task<IActionResult> PostLogin([FromBody] LoginDto loginDto)
        {

            //var cookieOptions = new CookieOptions
            //{
            //    HttpOnly = true,
            //    Expires = DateTime.SpecifyKind(DateTime.UtcNow, DateTimeKind.Utc).AddDays(30),
            //    Secure = true,
            //    SameSite = SameSiteMode.None
            //};

            //Response.Cookies.Append(CookieKey, refreshToken, cookieOptions);

            var user = _context.Users.FirstOrDefault(u => u.Login == loginDto.Login);
            if(user != null)
            {
                if (loginDto.Password != null && user.VerifyPasswordHash(loginDto.Password.ToString()))
                {
                    return StatusCode(200, new UserDto() { JwtToken = _jwtService.GenerateAuthorizationToken(user.UserId, "user"), UserId = user.UserId });
                }
                else { return StatusCode(400, new ErrorDto() { Id = Guid.NewGuid().ToString(), Message = "Invalid password", Code = "401" }); }
            }
            else if (user == null) { return StatusCode(400, new ErrorDto() { Id = Guid.NewGuid().ToString(), Message = "User not found", Code = "404" }); }

            //TODO: Uncomment the next line to return response 200 or use other options such as return this.NotFound(), return this.BadRequest(..), ...
            // return StatusCode(200, UserDto);
            //TODO: Uncomment the next line to return response 400 or use other options such as return this.NotFound(), return this.BadRequest(..), ...
            // return StatusCode(400, ErrorDto);

            throw new NotImplementedException();
        }

        /// <summary>
        /// Refresh JWT Token
        /// </summary>
        /// <remarks>Refresh JWT token</remarks>
        /// <param name="refreshDto"></param>
        /// <response code="200">OK</response>
        /// <response code="400">Invalid refresh token</response>
        [HttpPost]
        [Route("refresh")]
        [AllowAnonymous]
        [SwaggerResponse(statusCode: 200, type: typeof(UserDto), description: "OK")]
        [SwaggerResponse(statusCode: 400, type: typeof(ErrorDto), description: "Invalid refresh token")]
        public async Task<IActionResult> PostRefresh([FromBody] RefreshDto refreshDto)
        {
            var refreshToken = Request.Cookies[CookieKey];

            //var cookieOptions = new CookieOptions
            //{
            //    HttpOnly = true,
            //    Expires = DateTime.SpecifyKind(DateTime.UtcNow, DateTimeKind.Utc).AddDays(30),
            //    Secure = true,
            //    SameSite = SameSiteMode.None
            //};

            //Response.Cookies.Append(CookieKey, refreshToken, cookieOptions);

            //TODO: Uncomment the next line to return response 200 or use other options such as return this.NotFound(), return this.BadRequest(..), ...
            // return StatusCode(200, UserDto);
            //TODO: Uncomment the next line to return response 400 or use other options such as return this.NotFound(), return this.BadRequest(..), ...
            // return StatusCode(400, ErrorDto);

            throw new NotImplementedException();
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
        public async Task<IActionResult> PostRegister([FromBody] RegisterDto registerDto)
        {
            //TODO: Send request to User Profile API to create user profile

            // Check if login exists in db
            var existing_login = _context.Users.FirstOrDefault(u => u.Login.ToLower() == registerDto.Login.ToLower());
            var existing_email = _context.Users.FirstOrDefault(u => u.Email == registerDto.Email);
            if (existing_email != null || existing_login != null)
            {
                string message = string.Empty;
                if (existing_login != null) { message += "Login: " + registerDto.Login.ToString() + " "; }
                if (existing_email != null) 
                { 
                    if (message == string.Empty) { message += "Email: " + registerDto.Email.ToString() + " "; }
                    else { message += "and Email: " + registerDto.Email.ToString() + " "; }
                }
                return StatusCode(400, new ErrorDto() { Id = Guid.NewGuid().ToString(), Message = message + "is already exist!", Code = "409" });
            }


            // If doesnt exist - add to db
            else if (existing_email == null && existing_login == null)
            {
                // Password verivication required!!!!!!

                //Verivication email adress
                try
                {
                    var addr = new System.Net.Mail.MailAddress(registerDto.Email);
                }
                catch
                {
                    return StatusCode(400, new ErrorDto() { Id = Guid.NewGuid().ToString(), Message = "Invalid email format", Code = "409" });
                }
                User user = new User() { UserId = Guid.NewGuid().ToString(), Login = registerDto.Login, Email = registerDto.Email, Role = "user" };
                user.CreatePasswordHash(registerDto.Password);
                _context.Users.Add(user);
                using (var transaction = _context.Database.BeginTransaction())
                {
                    try
                    {
                        await _context.SaveChangesAsync();
                        transaction.Commit();
                    }
                    catch (Exception ex)
                    {
                        transaction.Rollback();
                        Log.Debug(ex.Message);
                    }
                }
                return StatusCode(200, new UserDto() { JwtToken = _jwtService.GenerateAuthorizationToken(user.UserId, "user"), UserId = user.UserId });
            }

            //TODO: Uncomment the next line to return response 200 or use other options such as return this.NotFound(), return this.BadRequest(..), ...
            // return StatusCode(200, UserDto);
            //TODO: Uncomment the next line to return response 400 or use other options such as return this.NotFound(), return this.BadRequest(..), ...
            // return StatusCode(400, ErrorDto);

            throw new NotImplementedException();
        }

        /// <summary>
        /// Update User Data
        /// </summary>
        /// <remarks>Update user login, password, email</remarks>
        /// <param name="updateUserDto"></param>
        /// <response code="200">OK</response>
        /// <response code="400">Old and new passwords doesn&#39;t match</response>
        /// <response code="401">Unauthorized</response>
        [HttpPut]
        [Route("update-user")]
        [Authorize(Roles = "User,Admin")]
        [SwaggerResponse(statusCode: 400, type: typeof(ErrorDto), description: "Old and new passwords doesn`t match")]
        public async Task<IActionResult> PutUpdateUser([FromBody] UpdateUserDto updateUserDto)
        {

            //TODO: Uncomment the next line to return response 200 or use other options such as return this.NotFound(), return this.BadRequest(..), ...
            // return StatusCode(200);
            //TODO: Uncomment the next line to return response 400 or use other options such as return this.NotFound(), return this.BadRequest(..), ...
            // return StatusCode(400, ErrorDto);

            throw new NotImplementedException();
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
            Logger.Debug("Start GetGeneratePassword(password: {@password})", password);
            Dictionary<string, string> passwordData = new();

            using var hmac = new HMACSHA512();
            passwordData["Salt"] = Convert.ToBase64String(hmac.Key);
            passwordData["Hash"] = Convert.ToBase64String(hmac.ComputeHash(Encoding.UTF8.GetBytes(password)));

            Logger.Debug("Result GetGeneratePassword(passwordData: {@passwordData})", passwordData);
            return StatusCode(200, passwordData);
        }
    }
}
