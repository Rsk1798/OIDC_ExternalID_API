using System.ComponentModel.DataAnnotations;
using System.ComponentModel;

namespace OIDC_ExternalID_API.Models
{
    /// <summary>
    /// Model for updating specific user attributes in Microsoft Graph API
    /// </summary>
    public class UserUpdateModel
    {
        /// <summary>
        /// User's display name (max 256 characters)
        /// </summary>
        /// <example>John Doe</example>
        [StringLength(256)]
        [Description("User's display name")]
        public string? DisplayName { get; set; }

        /// <summary>
        /// User's job title (max 256 characters)
        /// </summary>
        /// <example>Software Engineer</example>
        [StringLength(256)]
        [Description("User's job title")]
        public string? JobTitle { get; set; }

        /// <summary>
        /// User's department (max 256 characters)
        /// </summary>
        /// <example>Engineering</example>
        [StringLength(256)]
        [Description("User's department")]
        public string? Department { get; set; }
    }
}