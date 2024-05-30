using MassTransit;
using System.ComponentModel.DataAnnotations;

namespace AuthenticationAPI.MassTransit.Events
{
    /// <summary>
    /// Model for CreateUserProfileEvent
    /// </summary>
    [EntityName("user-profile-api-create-user-profile")]
    [MessageUrn("CreateUserProfileEvent")]
    public class CreateUserProfileEvent
    {
        /// <summary>
        /// Gets or Sets Name
        /// </summary>
        [Required]
        public string Name { get; set; } = null!;

        /// <summary>
        /// Gets or Sets Email
        /// </summary>
        [Required]
        public string Email { get; set; } = null!;
    }
}
