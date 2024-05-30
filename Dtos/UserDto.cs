using System;
using System.Linq;
using System.Text;
using System.Collections.Generic;
using System.ComponentModel;
using System.ComponentModel.DataAnnotations;
using System.Runtime.Serialization;
using System.Text.Json;

namespace AuthenticationAPI.Dtos
{
    /// <summary>
    /// Model for authentication response data
    /// </summary>
    [DataContract]
    public partial class UserDto
    {
        /// <summary>
        /// Gets or Sets JwtToken
        /// </summary>
        [Required]
        public string JwtToken { get; set; } = null!;

        /// <summary>
        /// Gets or Sets UserId
        /// </summary>
        [Required]
        public string UserId { get; set; } = null!;
    }
}
