namespace OIDC_ExternalID_API.Models
{
    public class UserUpdateModel
    {
        public string DisplayName { get; set; }
        public string JobTitle { get; set; }
        public string Department { get; set; }
        // Add other fields as needed for limited updates
    }
}