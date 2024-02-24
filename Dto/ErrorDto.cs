using System.ComponentModel.DataAnnotations;
using System.Text;

namespace AuthenticationAPI.Models
{
    /// <summary>
    /// 
    /// </summary>
    public class ErrorDto
    {
        /// <summary>
        /// Gets or Sets Id
        /// </summary>
        [Required]
        public string Id { get; set; } = null!;

        /// <summary>
        /// Gets or Sets Message
        /// </summary>
        [Required]
        public string Message { get; set; } = null!;

        /// <summary>
        /// Gets or Sets Code
        /// </summary>
        [Required]
        public string Code { get; set; } = null!;

        public ErrorDto(string message, string code)
        {
            Id = Guid.NewGuid().ToString();
            Message = message;
            Code = code;
        }

        public ErrorDto()
        {
            Id = Guid.NewGuid().ToString();
            Message = string.Empty;
            Code = string.Empty;
        }

        /// <summary>
        /// Returns the string presentation of the object
        /// </summary>
        /// <returns>String presentation of the object</returns>
        public override string ToString()
        {
            var sb = new StringBuilder();
            sb.Append("class ErrorDto {\n");
            sb.Append("  Id: ").Append(Id).Append("\n");
            sb.Append("  Message: ").Append(Message).Append("\n");
            sb.Append("  Code: ").Append(Code).Append("\n");
            sb.Append("}\n");
            return sb.ToString();
        }
    }
}
