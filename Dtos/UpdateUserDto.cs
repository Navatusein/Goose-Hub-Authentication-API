using System.ComponentModel.DataAnnotations;
using System.Text;

namespace AuthenticationAPI.Dtos
{
    /// <summary>
    /// Model for update user data
    /// </summary>
    public partial class UpdateUserDto
    {
        /// <summary>
        /// Gets or Sets Email
        /// </summary>
        [Required]
        public string Email { get; set; } = null!;

        /// <summary>
        /// Gets or Sets OldPassword
        /// </summary>
        [Required]
        public string OldPassword { get; set; } = null!;

        /// <summary>
        /// Gets or Sets NewPassword
        /// </summary>
        public string? NewPassword { get; set; }
    }
}
