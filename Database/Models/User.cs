using System.Security.Cryptography;

namespace AuthenticationAPI.Database.Models
{
    /// <summary>
    /// Model for store user data
    /// </summary>
    public class User
    {
        /// <summary>
        /// Id in database
        /// </summary>
        [System.ComponentModel.DataAnnotations.Key]
        public int Id { get; set; }

        /// <summary>
        /// User id
        /// </summary>
        public string UserId { get; set; } = null!;

        /// <summary>
        /// user`s login
        /// </summary>
        public string Login { get; set; } = null!;

        /// <summary>
        /// User`s email
        /// </summary>
        public string Email { get; set; } = null!;

        /// <summary>
        /// Role of user
        /// </summary>
        public string Role { get; set; } = null!;

        /// <summary>
        /// Hashed password
        /// </summary>
        public string PasswordHash { get; set; } = null!;

        /// <summary>
        /// Salted password
        /// </summary>
        public string PasswordSalt { get; set; } = null!;

        /// <summary>
        /// Verify received hash of password
        /// </summary>
        /// <param name="password">User password</param>
        /// <returns>True if user password</returns>
        public bool VerifyPasswordHash(string password)
        {
            byte[] passwordHashBytes = Convert.FromBase64String(this.PasswordHash);
            byte[] passwordSaltBytes = Convert.FromBase64String(this.PasswordSalt);

            using var hmac = new HMACSHA512(passwordSaltBytes);
            var computedHash = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));
            return computedHash.SequenceEqual(passwordHashBytes);
        }

        /// <summary>
        ///  Create Hash for user`s password
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
