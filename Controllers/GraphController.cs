using Microsoft.AspNetCore.Mvc;
using Microsoft.Graph;
using Microsoft.Graph.Models;
using Microsoft.Graph.Models.ODataErrors;
using OIDC_ExternalID_API.Models;
using Microsoft.AspNetCore.Authorization;

namespace OIDC_ExternalID_API.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class GraphController : ControllerBase
    {


        private readonly GraphServiceClient _graphServiceClient;


        // This injects the GraphServiceClient into your controller
        public GraphController(GraphServiceClient graphServiceClient)
        {
            _graphServiceClient = graphServiceClient;
        }



        [HttpPost("invite")]
        [ApiExplorerSettings(IgnoreApi = true)]
        public async Task<IActionResult> InviteUser(string email)
        {
            var invitation = new Invitation
            {
                InvitedUserEmailAddress = email,
                InviteRedirectUrl = "https://localhost:7110/", // This URL needs to be one of the redirect URIs registered in your app registration
                SendInvitationMessage = true,
                InvitedUserMessageInfo = new InvitedUserMessageInfo
                {
                    CustomizedMessageBody = "Hello! You've been invited to collaborate with us. Please accept the invitation to get started."
                }
            };

            try
            {
                // This line calls the Graph API behind the scenes
                var result = await _graphServiceClient.Invitations.PostAsync(invitation);
                return Ok(result);
            }
            catch (ODataError odataError)
            {
                return BadRequest(odataError.Error);
            }
        }



        // [HttpGet("Get_User-by-userobjID")]
        [HttpGet("getUserById")]
        public async Task<IActionResult> GetUser([FromQuery] string idOrEmail)
        {
            try
            {
                // This line calls the Graph API to get user details
                var user = await _graphServiceClient.Users[idOrEmail].GetAsync();
                return Ok(user);
            }
            catch (ODataError odataError)
            {
                return BadRequest(odataError.Error);
            }
        }




        // [HttpGet("Get_User/by-email")]
        [HttpGet("getUserByEmail")]
        public async Task<IActionResult> GetUserByEmail([FromQuery] string email)
        {
            try
            {
                var users = await _graphServiceClient.Users
                    .GetAsync(requestConfig =>
                    {
                        requestConfig.QueryParameters.Filter = $"mail eq '{email}' or otherMails/any(x:x eq '{email}')";
                    });

                var user = users?.Value?.FirstOrDefault();
                if (user == null)
                    return NotFound("User not found.");

                return Ok(user);
            }
            catch (ODataError odataError)
            {
                return BadRequest(odataError.Error);
            }
        }




        // [HttpPatch("Update_User-by-userobjID")]
        [HttpPatch("updateUserById")]
        public async Task<IActionResult> UpdateUser([FromQuery] string idOrEmail, [FromBody] Dictionary<string, object> updates)
        {
            try
            {
                var user = new User();
                foreach (var kvp in updates)
                {
                    user.AdditionalData[kvp.Key] = kvp.Value;
                }

                // This line calls the Graph API to update a user
                await _graphServiceClient.Users[idOrEmail].PatchAsync(user);

                return Ok("User Updated Successfully.");

                // Fetch the updated user object
                //var updatedUser = await _graphServiceClient.Users[idOrEmail].GetAsync();
                //return Ok(updatedUser);
            }
            catch (ODataError odataError)
            {
                return BadRequest(odataError.Error);
            }
        }




        // [HttpPatch("UpdateUserLimitedAttributes-userobjID")]
        [HttpPatch("updateUserAttributesById")]
        public async Task<IActionResult> UpdateUserLimitedAttributes([FromQuery] string idOrEmail, [FromBody] UserUpdateModel updates)
        {
            try
            {
                var user = new User();
                if (updates.DisplayName != null)
                    user.DisplayName = updates.DisplayName;
                if (updates.JobTitle != null)
                    user.JobTitle = updates.JobTitle;
                if (updates.Department != null)
                    user.Department = updates.Department;
                // Add other fields as needed

                await _graphServiceClient.Users[idOrEmail].PatchAsync(user);

                return Ok("User Updated with Limited Attributes");
            }
            catch (ODataError odataError)
            {
                return BadRequest(odataError.Error);
            }
        }

        // [HttpDelete("Delete_User-by-userobjID")]
        [HttpDelete("deleteUserById")]
        public async Task<IActionResult> DeleteUser([FromQuery] string idOrEmail)
        {
            try
            {
                // This line calls the Graph API to delete a user
                await _graphServiceClient.Users[idOrEmail].DeleteAsync();
                return Ok("User deleted successfully.");
            }
            catch (ODataError odataError)
            {
                return BadRequest(odataError.Error);
            }
        }

        // [HttpDelete("Delete_User-by-email")]
        [HttpDelete("deleteUserByEmail")]
        public async Task<IActionResult> DeleteUserByEmail([FromQuery] string email)
        {
            try
            {
                // First, find the user by email
                var users = await _graphServiceClient.Users
                    .GetAsync(requestConfig =>
                    {
                        requestConfig.QueryParameters.Filter = $"mail eq '{email}' or otherMails/any(x:x eq '{email}')";
                    });

                var user = users?.Value?.FirstOrDefault();
                if (user == null)
                    return NotFound("User not found.");

                // Delete the user using their ID
                await _graphServiceClient.Users[user.Id].DeleteAsync();
                return Ok($"User with email '{email}' deleted successfully.");
            }
            catch (ODataError odataError)
            {
                return BadRequest(odataError.Error);
            }
        }

        // [HttpPatch("Change_Password-by-userobjID")]
        [HttpPatch("changePasswordById")]
        public async Task<IActionResult> ChangePassword([FromQuery] string idOrEmail, [FromBody] PasswordChangeRequest request)
        {
            try
            {
                if (string.IsNullOrEmpty(request.NewPassword))
                {
                    return BadRequest("New password is required.");
                }

                var passwordProfile = new PasswordProfile
                {
                    Password = request.NewPassword,
                    ForceChangePasswordNextSignIn = request.ForceChangePasswordNextSignIn ?? false,
                    ForceChangePasswordNextSignInWithMfa = request.ForceChangePasswordNextSignInWithMfa ?? false
                };

                var user = new User
                {
                    PasswordProfile = passwordProfile
                };

                // This line calls the Graph API to change the user's password
                await _graphServiceClient.Users[idOrEmail].PatchAsync(user);
                return Ok("Password changed successfully.");
            }
            catch (ODataError odataError)
            {
                return BadRequest(odataError.Error);
            }
        }

        // [HttpPatch("Change_Password-by-email")]
        [HttpPatch("changePasswordByEmail")]
        public async Task<IActionResult> ChangePasswordByEmail([FromQuery] string email, [FromBody] PasswordChangeRequest request)
        {
            try
            {
                if (string.IsNullOrEmpty(request.NewPassword))
                {
                    return BadRequest("New password is required.");
                }

                // First, find the user by email
                var users = await _graphServiceClient.Users
                    .GetAsync(requestConfig =>
                    {
                        requestConfig.QueryParameters.Filter = $"mail eq '{email}' or otherMails/any(x:x eq '{email}')";
                    });

                var user = users?.Value?.FirstOrDefault();
                if (user == null)
                    return NotFound("User not found.");

                var passwordProfile = new PasswordProfile
                {
                    Password = request.NewPassword,
                    ForceChangePasswordNextSignIn = request.ForceChangePasswordNextSignIn ?? false,
                    ForceChangePasswordNextSignInWithMfa = request.ForceChangePasswordNextSignInWithMfa ?? false
                };

                var userUpdate = new User
                {
                    PasswordProfile = passwordProfile
                };

                // Change the password using the user's ID
                await _graphServiceClient.Users[user.Id].PatchAsync(userUpdate);
                return Ok($"Password changed successfully for user with email '{email}'.");
            }
            catch (ODataError odataError)
            {
                return BadRequest(odataError.Error);
            }
        }

        [HttpPost("changeOwnPassword")]
        [Authorize]
        public async Task<IActionResult> ChangeOwnPassword([FromBody] SelfPasswordChangeRequest request)
        {
            if (request.NewPassword != request.ConfirmNewPassword)
                return BadRequest("New password and confirmation do not match.");

            if (string.IsNullOrEmpty(request.CurrentPassword) || string.IsNullOrEmpty(request.NewPassword))
                return BadRequest("Current and new password are required.");

            try
            {
                // This requires delegated permissions and a user token
                await _graphServiceClient.Me.ChangePassword.PostAsync(new Microsoft.Graph.Me.ChangePassword.ChangePasswordPostRequestBody
                {
                    CurrentPassword = request.CurrentPassword,
                    NewPassword = request.NewPassword
                });
                return Ok("Password changed successfully.");
            }
            catch (ODataError odataError)
            {
                return BadRequest(odataError.Error);
            }
        }

    }
} 
