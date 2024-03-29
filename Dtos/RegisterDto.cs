using System.Text;
using System.ComponentModel.DataAnnotations;

namespace AuthenticationAPI.Dtos
{
    /// <summary>
    /// Model with registration data
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
    }
}
