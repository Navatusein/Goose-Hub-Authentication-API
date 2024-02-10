using System.Text;
using System.ComponentModel.DataAnnotations;

namespace AuthenticationAPI.Models
{
    /// <summary>
    /// 
    /// </summary>
    public partial class RegisterDto
    {
        /// <summary>
        /// Gets or Sets Login
        /// </summary>
        [Required]
        public string Login { get; set; } = null!;

        /// <summary>
        /// Gets or Sets Password
        /// </summary>
        [Required]
        public string Password { get; set; } = null!;

        /// <summary>
        /// Gets or Sets Email
        /// </summary>
        [Required]
        public string Email { get; set; } = null!;

        /// <summary>
        /// Returns the string presentation of the object
        /// </summary>
        /// <returns>String presentation of the object</returns>
        public override string ToString()
        {
            var sb = new StringBuilder();
            sb.Append("class RegisterDto {\n");
            sb.Append("  Login: ").Append(Login).Append("\n");
            sb.Append("  Password: ").Append(Password).Append("\n");
            sb.Append("  Email: ").Append(Email).Append("\n");
            sb.Append("}\n");
            return sb.ToString();
        }
    }
}
