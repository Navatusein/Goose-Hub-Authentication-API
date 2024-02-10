using System.Text;

namespace AuthenticationAPI.Models
{
    /// <summary>
    /// 
    /// </summary>
    public partial class RefreshDto
    {
        /// <summary>
        /// Gets or Sets JwtToken
        /// </summary>
        public string JwtToken { get; set; } = null!;

        /// <summary>
        /// Gets or Sets UserId
        /// </summary>
        public string UserId { get; set; } = null!;

        /// <summary>
        /// Returns the string presentation of the object
        /// </summary>
        /// <returns>String presentation of the object</returns>
        public override string ToString()
        {
            var sb = new StringBuilder();
            sb.Append("class RefreshDto {\n");
            sb.Append("  JwtToken: ").Append(JwtToken).Append("\n");
            sb.Append("  UserId: ").Append(UserId).Append("\n");
            sb.Append("}\n");
            return sb.ToString();
        }
    }
}
