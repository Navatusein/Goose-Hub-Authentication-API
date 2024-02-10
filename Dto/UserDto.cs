using System;
using System.Linq;
using System.Text;
using System.Collections.Generic;
using System.ComponentModel;
using System.ComponentModel.DataAnnotations;
using System.Runtime.Serialization;
using System.Text.Json;

namespace AuthenticationAPI.Models
{ 
    /// <summary>
    /// 
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

        /// <summary>
        /// Returns the string presentation of the object
        /// </summary>
        /// <returns>String presentation of the object</returns>
        public override string ToString()
        {
            var sb = new StringBuilder();
            sb.Append("class UserDto {\n");
            sb.Append("  JwtToken: ").Append(JwtToken).Append("\n");
            sb.Append("  UserId: ").Append(UserId).Append("\n");
            sb.Append("}\n");
            return sb.ToString();
        }
    }
}
