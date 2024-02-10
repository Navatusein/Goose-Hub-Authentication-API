using System.ComponentModel.DataAnnotations;
using System.Text;

namespace AuthenticationAPI.Models
{
    /// <summary>
    /// 
    /// </summary>
    public partial class UpdateUserDto
    {
        /// <summary>
        /// Gets or Sets UserId
        /// </summary>
        [Required]
        public string UserId { get; set; } = null!;

        /// <summary>
        /// Gets or Sets Login
        /// </summary>
        [Required]
        public string Login { get; set; } = null!;

        /// <summary>
        /// Gets or Sets OldPassword
        /// </summary>
        [Required]
        public string OldPassword { get; set; } = null!;

        /// <summary>
        /// Gets or Sets NewPassword
        /// </summary>
        [Required]
        public string NewPassword { get; set; } = null!;

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
            sb.Append("class UpdateUserDto {\n");
            sb.Append("  UserId: ").Append(UserId).Append("\n");
            sb.Append("  Login: ").Append(Login).Append("\n");
            sb.Append("  OldPassword: ").Append(OldPassword).Append("\n");
            sb.Append("  NewPassword: ").Append(NewPassword).Append("\n");
            sb.Append("  Email: ").Append(Email).Append("\n");
            sb.Append("}\n");
            return sb.ToString();
        }
    }
}
