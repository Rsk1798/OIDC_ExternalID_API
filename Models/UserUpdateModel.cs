namespace OIDC_ExternalID_API.Models
{
    public class UserUpdateModel
    {

        // Add other fields you want to allow for update
        public string? DisplayName { get; set; }
        public string? JobTitle { get; set; }
        public string? Department { get; set; }

    }

    public class PasswordChangeRequest
    {
        public string NewPassword { get; set; } = string.Empty;
        public bool? ForceChangePasswordNextSignIn { get; set; }
        public bool? ForceChangePasswordNextSignInWithMfa { get; set; }
    }

    public class SelfPasswordChangeRequest
    {
        public string CurrentPassword { get; set; } = string.Empty;
        public string NewPassword { get; set; } = string.Empty;
        public string ConfirmNewPassword { get; set; } = string.Empty;
    }
}
