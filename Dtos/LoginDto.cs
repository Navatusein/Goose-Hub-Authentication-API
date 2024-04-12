using System.ComponentModel.DataAnnotations;
using System.Text;

namespace AuthenticationAPI.Dtos
{
    /// <summary>
    /// Model with authentication data
    /// </summary>
    public partial class LoginDto
    {
        /// <summary>
        /// Gets or Sets Email
        /// </summary>
        [Required]
        public string Email { get; set; } = null!;

        /// <summary>
        /// Gets or Sets Password
        /// </summary>
        [Required]
        public string Password { get; set; } = null!;
    }
}
