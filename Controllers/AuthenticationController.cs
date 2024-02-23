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
using System.Xml;

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
            var user = _context.Users.FirstOrDefault(u => u.Login.ToLower() == loginDto.Login.ToLower());
            Logger.Debug($"Start login (user: {user.UserId})");
            
            if(user == null)
            {
                Logger.Debug("Post login: error - user not found");
                return StatusCode(400, new ErrorDto { Id = Guid.NewGuid().ToString(), Message = "User not found", Code = "404" });
            }

            if (!user.VerifyPasswordHash(loginDto.Password))
            {
                Logger.Debug("Post login: error - invalid password");
                return StatusCode(400, new ErrorDto { Id = Guid.NewGuid().ToString(), Message = "Invalid password", Code = "401" });
            }

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
            Logger.Debug($"Post login finished, user: {dto.UserId}, token: {dto.JwtToken}");
            return StatusCode(200, dto);


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
            Logger.Debug($"Start refresh (user: {refreshDto.UserId})");
            var refreshToken = Request.Cookies[CookieKey];
            Logger.Debug($"Refresh token of user {refreshDto.UserId}: {refreshToken}");
            
            if(refreshToken == null)
            {
                Logger.Debug($"Post Refresh: error - Refresh token is null");
                return StatusCode(400, new ErrorDto() { Id = Guid.NewGuid().ToString(), Message = "Invalid refresh token", Code = "401" });
            }

            if (!_jwtService.ValidateRefreshToken(refreshToken, refreshDto.UserId))
            {
                Logger.Debug($"Post Refresh: error - Invalid refresh token");
                return StatusCode(400, new ErrorDto() { Id = Guid.NewGuid().ToString(), Message = "Invalid refresh token", Code = "401" });
            }

            var user = _context.Users.FirstOrDefault(u => u.UserId == refreshDto.UserId);
            if(user == null)
            {
                Logger.Debug($"Post Refresh: error - no user exists");
                return StatusCode(400, new ErrorDto() { Id = Guid.NewGuid().ToString(), Message = "Invalid user data", Code = "401" });
            }

            refreshToken = _jwtService.GenerateRefreshToken(refreshToken);

            var cookieOptions = new CookieOptions
            {
                HttpOnly = true,
                Expires = DateTime.SpecifyKind(DateTime.UtcNow, DateTimeKind.Utc).AddDays(30),
                Secure = true,
                SameSite = SameSiteMode.None
            };

            Response.Cookies.Append(CookieKey, refreshToken, cookieOptions);
            UserDto dto = new UserDto()
            {
                JwtToken = refreshToken,
                UserId = user.UserId
            };

            return Ok(dto);

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
            Logger.Debug($"Start register user login: {registerDto.Login}");
            var user_check = _context.Users.FirstOrDefault(u => u.Login.ToLower() == registerDto.Login.ToLower());

            if (user_check != null)
            {
                Logger.Debug($"Post register: error - login exists");
                return StatusCode(400, new ErrorDto() { Id = Guid.NewGuid().ToString(), Message = "Login is already taken", Code = "401" });
            }

            try
            {
                var tmp = new System.Net.Mail.MailAddress(registerDto.Email);
            }
            catch
            {
                Logger.Debug($"Post register: error - email is not exist");
                return StatusCode(400, new ErrorDto() { Id = Guid.NewGuid().ToString(), Message = "Invalid email", Code = "401" });
            }

            User user = new User()
            {
                UserId = Guid.NewGuid().ToString(),
                Login = registerDto.Login,
                Email = registerDto.Email,
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

            Logger.Debug($"Post register finished, user login: {dto.UserId}, token: {dto.JwtToken}");
            return StatusCode(200, dto);

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

            var user = _context.Users.FirstOrDefault(x => x.UserId == updateUserDto.UserId);
            if (user == null)
            {
                return StatusCode(400, new ErrorDto { Id = Guid.NewGuid().ToString(), Message = "User not found", Code = "404" });
            }
            else if (user != null)
            {
                if (user.VerifyPasswordHash(updateUserDto.OldPassword.ToString()) &&
                    !updateUserDto.OldPassword.ToString().Equals(updateUserDto.NewPassword.ToString()))
                {
                    user.Login = updateUserDto.Login;
                    user.CreatePasswordHash(updateUserDto.NewPassword);
                    user.Email = updateUserDto.Email;
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
                }
            }
            

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
