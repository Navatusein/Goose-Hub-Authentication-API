using Microsoft.IdentityModel.Tokens;
using System.Data;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace AuthenticationAPI.Service
{
    /// <summary>
    /// Service for JWT token generation
    /// </summary>
    public class JwtService
    {
        private static Serilog.ILogger Logger => Serilog.Log.ForContext<JwtService>();
        private readonly IConfiguration _config;

        /// <summary>
        /// Constructor of class JwtService
        /// </summary>
        public JwtService(IConfiguration config)
        {
            _config = config;
        }

        /// <summary>
        /// Validate refresh JWT token
        /// </summary>
        /// <param name="token"></param>
        /// <param name="userId"></param>
        /// <returns>Boolean valid token or not</returns>
        public bool ValidateRefreshToken(string token, string userId)
        {
            var tokenHandler = new JwtSecurityTokenHandler();

            var validationParameters = new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidateAudience = true,
                ValidateLifetime = true,
                ValidateIssuerSigningKey = true,
                ValidIssuer = _config["RefreshJWT:Issuer"],
                ValidAudience = _config["RefreshJWT:Audience"],
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config["FrontendRefreshJWT:Key"]!))
            };

            if (!tokenHandler.CanReadToken(token))
                return false;

            try
            {
                var principal = tokenHandler.ValidateToken(token, validationParameters, out var validatedToken);

                if (principal.HasClaim(c => c.Type == "id"))
                    return userId == principal.Claims.First(c => c.Type == "userId").Value;
            }
            catch (Exception exception)
            {
                Logger.Error("Refresh token validation error: @1", exception);
            }

            return false;
        }

        /// <summary>
        /// Generate authorization JWT token 
        /// </summary>
        /// <param name="userId">Id of user</param>
        /// <param name="role">User role</param>
        /// <returns>Authorization JWT token</returns>
        public string GenerateAuthorizationToken(string userId, string role)
        {
            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config["AuthorizeJWT:Key"]!));
            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

            var claims = new[]
            {
                new Claim("userId", userId),
                new Claim(ClaimTypes.Role, role)
            };

            var token = new JwtSecurityToken(
                _config["AuthorizeJWT:Issuer"],
                _config["AuthorizeJWT:Audience"],
                claims,
                expires: DateTime.Now.AddMinutes(60),
                signingCredentials: credentials);

            return new JwtSecurityTokenHandler().WriteToken(token);
        }

        /// <summary>
        /// Generate refresh JWT token
        /// </summary>
        /// <param name="userId">Id of user</param>
        /// <returns>Refresh JWT token</returns>
        public string GenerateRefreshToken(string userId)
        {
            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config["RefreshJWT:Key"]!));
            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

            var claims = new[]
            {
                new Claim("UserId", userId)
            };

            var token = new JwtSecurityToken(
                _config["RefreshJWT:Issuer"],
                _config["RefreshJWT:Audience"],
                claims,
                expires: DateTime.Now.AddDays(30),
                signingCredentials: credentials);

            return new JwtSecurityTokenHandler().WriteToken(token);
        }
    }
}
