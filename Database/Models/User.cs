using System.Security.Cryptography;

namespace AuthenticationAPI.Database.Models
{
    /// <summary>
    /// 
    /// </summary>
    public class User
    {
        /// <summary>
        /// 
        /// </summary>
        public int Id { get; set; }

        /// <summary>
        /// 
        /// </summary>
        public string UserId { get; set; } = null!;

        /// <summary>
        /// 
        /// </summary>
        public string Login { get; set; } = null!;

        /// <summary>
        /// 
        /// </summary>
        public string Email { get; set; } = null!;

        /// <summary>
        /// 
        /// </summary>
        public string Role { get; set; } = null!;

        /// <summary>
        /// 
        /// </summary>
        public string PasswordHash { get; set; } = null!;

        /// <summary>
        /// 
        /// </summary>
        public string PasswordSalt { get; set; } = null!;

        /// <summary>
        /// 
        /// </summary>
        /// <param name="password">User password</param>
        /// <returns>True if user password </returns>
        public bool VerifyPasswordHash(string password)
        {
            byte[] passwordHashBytes = Convert.FromBase64String(this.PasswordHash);
            byte[] passwordSaltBytes = Convert.FromBase64String(this.PasswordSalt);

            using var hmac = new HMACSHA512(passwordSaltBytes);
            var computedHash = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));
            return computedHash.SequenceEqual(passwordHashBytes);
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="password">User password</param>
        public void CreatePasswordHash(string password)
        {
            using var hmac = new HMACSHA512();
            this.PasswordSalt = Convert.ToBase64String(hmac.Key);
            this.PasswordHash = Convert.ToBase64String(hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password)));
        }
    }
}
