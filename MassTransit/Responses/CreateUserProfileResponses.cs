using MassTransit;

namespace AuthenticationAPI.MassTransit.Responses
{
    /// <summary>
    /// Model for response on CreateUserProfileEvent
    /// </summary>
    [MessageUrn("CreateUserProfileResponse")]
    public class CreateUserProfileResponse
    {
        /// <summary>
        /// Gets or Sets UserProfileId
        /// </summary>
        public string UserProfileId { get; set; } = null!;
    }
}
