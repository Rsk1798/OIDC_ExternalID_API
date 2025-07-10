using Microsoft.AspNetCore.Mvc;
using Microsoft.Graph;
using Microsoft.Graph.Models;
using Microsoft.Graph.Models.ODataErrors;
using OIDC_ExternalID_API.Models;
using Microsoft.AspNetCore.Authorization;
using System.Net.Http.Json;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Net;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Newtonsoft.Json;

namespace OIDC_ExternalID_API.Controllers
{
    [ApiController]
    [Route("[controller]")]
    [Authorize]
    public class GraphController : ControllerBase
    {


        private readonly GraphServiceClient _graphServiceClient;
        private readonly IHttpClientFactory _httpClientFactory;
        private readonly IHttpContextAccessor _httpContextAccessor;


        // This injects the GraphServiceClient into your controller
        public GraphController(GraphServiceClient graphServiceClient, IHttpClientFactory httpClientFactory, IHttpContextAccessor httpContextAccessor)
        {
            _graphServiceClient = graphServiceClient;
            _httpClientFactory = httpClientFactory;
            _httpContextAccessor = httpContextAccessor;
        }



        [HttpGet("Readme-Instructuons-API-Endpoints")]
        [AllowAnonymous]
        public IActionResult GetReadme()
        {
            var readme = System.IO.File.ReadAllText("README.md");
            return Content(readme, "text/markdown");
        }

        [HttpGet("me")]
        [Authorize]
        public IActionResult GetCurrentUser()
        {
            try
            {
                var userId = User.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value;
                var username = User.FindFirst(System.Security.Claims.ClaimTypes.Name)?.Value;
                var scope = User.FindFirst("scope")?.Value;

                return Ok(new
                {
                    UserId = userId,
                    Username = username,
                    Scope = scope,
                    IsAuthenticated = User.Identity.IsAuthenticated,
                    Claims = User.Claims.Select(c => new { c.Type, c.Value }).ToList()
                });
            }
            catch (Exception ex)
            {
                return BadRequest($"Error getting current user: {ex.Message}");
            }
        }

        [HttpPost("invite")]
        [Authorize]
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
        [Authorize]
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
        [Authorize]
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
        [Authorize]
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





        [HttpPatch("updateUserByEmail")]
        [Authorize]
        public async Task<IActionResult> UpdateUserByEmail([FromQuery] string email, [FromBody] Dictionary<string, object> updates)
        {
            try
            {
                // Find the user by email
                var users = await _graphServiceClient.Users
                    .GetAsync(requestConfig =>
                    {
                        requestConfig.QueryParameters.Filter = $"mail eq '{email}' or otherMails/any(x:x eq '{email}')";
                    });

                var user = users?.Value?.FirstOrDefault();
                if (user == null)
                    return NotFound("User not found.");

                var userUpdate = new User();
                foreach (var kvp in updates)
                {
                    userUpdate.AdditionalData[kvp.Key] = kvp.Value;
                }

                await _graphServiceClient.Users[user.Id].PatchAsync(userUpdate);

                return Ok($"User with email '{email}' updated successfully.");
            }
            catch (ODataError odataError)
            {
                return BadRequest(odataError.Error);
            }
        }




        // [HttpPatch("UpdateUserLimitedAttributes-userobjID")]
        [HttpPatch("updateUserAttributesById")]
        [Authorize]
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




        [HttpPatch("updateUserAttributesByEmail")]
        [Authorize]
        public async Task<IActionResult> UpdateUserAttributesByEmail([FromQuery] string email, [FromBody] UserUpdateModel updates)
        {
            try
            {
                // Find the user by email
                var users = await _graphServiceClient.Users
                    .GetAsync(requestConfig =>
                    {
                        requestConfig.QueryParameters.Filter = $"mail eq '{email}' or otherMails/any(x:x eq '{email}')";
                    });

                var user = users?.Value?.FirstOrDefault();
                if (user == null)
                    return NotFound("User not found.");

                var userUpdate = new User();
                if (updates.DisplayName != null)
                    userUpdate.DisplayName = updates.DisplayName;
                if (updates.JobTitle != null)
                    userUpdate.JobTitle = updates.JobTitle;
                if (updates.Department != null)
                    userUpdate.Department = updates.Department;
                // Add other fields as needed

                await _graphServiceClient.Users[user.Id].PatchAsync(userUpdate);

                return Ok($"User with email '{email}' updated with limited attributes.");
            }
            catch (ODataError odataError)
            {
                return BadRequest(odataError.Error);
            }
        }




        // [HttpDelete("Delete_User-by-userobjID")]
        [HttpDelete("deleteUserById")]
        [Authorize]
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
        [Authorize]
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

        [HttpPost("changePassword")]
        [Authorize]
        public async Task<IActionResult> ChangePassword([FromBody] ChangePasswordModel model)
        {
            var accessToken = await GetAccessTokenAsync();
            if (string.IsNullOrEmpty(accessToken))
                return Unauthorized();

            var client = _httpClientFactory.CreateClient();
            var request = new HttpRequestMessage(HttpMethod.Post, "https://graph.microsoft.com/v1.0/me/changePassword");
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
            request.Content = new StringContent(JsonConvert.SerializeObject(new
            {
                currentPassword = model.CurrentPassword,
                newPassword = model.NewPassword
            }), Encoding.UTF8, "application/json");

            var response = await client.SendAsync(request);
            if (response.StatusCode == HttpStatusCode.NoContent)
                return NoContent();

            var error = await response.Content.ReadAsStringAsync();
            return StatusCode((int)response.StatusCode, error);
        }

        [HttpPatch("resetPasswordById")]
        [Authorize]
        public async Task<IActionResult> ResetPasswordById([FromQuery] string idOrEmail, [FromBody] ResetPasswordModel model)
        {
            try
            {
                var user = new User
                {
                    PasswordProfile = new PasswordProfile
                    {
                        Password = model.NewPassword,
                        ForceChangePasswordNextSignIn = model.ForceChangePasswordNextSignIn,
                        ForceChangePasswordNextSignInWithMfa = model.ForceChangePasswordNextSignInWithMfa
                    }
                };

                // This line calls the Graph API to update the user's password profile
                await _graphServiceClient.Users[idOrEmail].PatchAsync(user);

                return Ok($"Password reset successfully for user {idOrEmail}. User will be required to change password on next sign-in: {model.ForceChangePasswordNextSignIn}");
            }
            catch (ODataError odataError)
            {
                return BadRequest(odataError.Error);
            }
        }

        [HttpPatch("resetPasswordByEmail")]
        [Authorize]
        public async Task<IActionResult> ResetPasswordByEmail([FromQuery] string email, [FromBody] ResetPasswordModel model)
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

                var userUpdate = new User
                {
                    PasswordProfile = new PasswordProfile
                    {
                        Password = model.NewPassword,
                        ForceChangePasswordNextSignIn = model.ForceChangePasswordNextSignIn,
                        ForceChangePasswordNextSignInWithMfa = model.ForceChangePasswordNextSignInWithMfa
                    }
                };

                // Update the user's password profile using their ID
                await _graphServiceClient.Users[user.Id].PatchAsync(userUpdate);

                return Ok($"Password reset successfully for user with email '{email}'. User will be required to change password on next sign-in: {model.ForceChangePasswordNextSignIn}");
            }
            catch (ODataError odataError)
            {
                return BadRequest(odataError.Error);
            }
        }

        [HttpPost("requestPasswordReset")]
        [AllowAnonymous]
        public async Task<IActionResult> RequestPasswordReset([FromBody] RequestPasswordResetModel model)
        {
            try
            {
                // First, verify the user exists
                var users = await _graphServiceClient.Users
                    .GetAsync(requestConfig =>
                    {
                        requestConfig.QueryParameters.Filter = $"mail eq '{model.Email}' or otherMails/any(x:x eq '{model.Email}')";
                    });

                var user = users?.Value?.FirstOrDefault();
                if (user == null)
                {
                    // Don't reveal if user exists or not for security
                    return Ok("If the email address exists in our system, a verification code has been sent.");
                }

                // Generate a verification code (6 digits)
                var verificationCode = GenerateVerificationCode();
                
                // Store the verification code with expiration (you might want to use a database or cache)
                // For demo purposes, we'll use a simple in-memory storage
                StoreVerificationCode(model.Email, verificationCode);

                // Send email with verification code
                // Note: In a real implementation, you would integrate with an email service
                // For now, we'll just return the code in the response for testing
                await SendVerificationEmail(model.Email, verificationCode);

                return Ok(new
                {
                    message = "If the email address exists in our system, a verification code has been sent.",
                    verificationCode = verificationCode, // Remove this in production
                    expiresIn = "15 minutes"
                });
            }
            catch (ODataError odataError)
            {
                return BadRequest(odataError.Error);
            }
        }

        [HttpPost("completePasswordReset")]
        [AllowAnonymous]
        public async Task<IActionResult> CompletePasswordReset([FromBody] SelfServicePasswordResetModel model)
        {
            try
            {
                // Verify the verification code
                if (!ValidateVerificationCode(model.Email, model.VerificationCode))
                {
                    return BadRequest("Invalid or expired verification code.");
                }

                // Find the user by email
                var users = await _graphServiceClient.Users
                    .GetAsync(requestConfig =>
                    {
                        requestConfig.QueryParameters.Filter = $"mail eq '{model.Email}' or otherMails/any(x:x eq '{model.Email}')";
                    });

                var user = users?.Value?.FirstOrDefault();
                if (user == null)
                {
                    return NotFound("User not found.");
                }

                // Update the user's password profile
                var userUpdate = new User
                {
                    PasswordProfile = new PasswordProfile
                    {
                        Password = model.NewPassword,
                        ForceChangePasswordNextSignIn = model.ForceChangePasswordNextSignIn,
                        ForceChangePasswordNextSignInWithMfa = model.ForceChangePasswordNextSignInWithMfa
                    }
                };

                await _graphServiceClient.Users[user.Id].PatchAsync(userUpdate);

                // Clear the verification code after successful reset
                ClearVerificationCode(model.Email);

                return Ok(new
                {
                    message = "Password reset successfully. You can now log in with your new password.",
                    forceChangePasswordNextSignIn = model.ForceChangePasswordNextSignIn
                });
            }
            catch (ODataError odataError)
            {
                return BadRequest(odataError.Error);
            }
        }

        private string GenerateVerificationCode()
        {
            // Generate a 6-digit verification code
            var random = new Random();
            return random.Next(100000, 999999).ToString();
        }

        private void StoreVerificationCode(string email, string code)
        {
            // In a real implementation, store this in a database or cache with expiration
            // For demo purposes, we'll use a simple dictionary
            // Note: This is not thread-safe and will be lost on app restart
            if (_verificationCodes == null)
                _verificationCodes = new Dictionary<string, (string code, DateTime expires)>();

            _verificationCodes[email.ToLower()] = (code, DateTime.UtcNow.AddMinutes(15));
        }

        private bool ValidateVerificationCode(string email, string code)
        {
            if (_verificationCodes == null)
                return false;

            var emailKey = email.ToLower();
            if (!_verificationCodes.ContainsKey(emailKey))
                return false;

            var (storedCode, expires) = _verificationCodes[emailKey];
            
            // Check if code has expired
            if (DateTime.UtcNow > expires)
            {
                _verificationCodes.Remove(emailKey);
                return false;
            }

            // Check if code matches
            return storedCode == code;
        }

        private void ClearVerificationCode(string email)
        {
            if (_verificationCodes != null)
            {
                _verificationCodes.Remove(email.ToLower());
            }
        }

        private async Task SendVerificationEmail(string email, string code)
        {
            // In a real implementation, integrate with an email service like:
            // - SendGrid
            // - Mailgun
            // - Azure Communication Services
            // - SMTP server
            
            // For demo purposes, we'll just log the email
            // In production, replace this with actual email sending logic
            var emailContent = $@"
                Password Reset Verification Code
                
                Your verification code is: {code}
                
                This code will expire in 15 minutes.
                
                If you didn't request this password reset, please ignore this email.
            ";

            // Log the email content (remove this in production)
            Console.WriteLine($"Email to {email}: {emailContent}");
            
            await Task.CompletedTask; // Simulate async email sending
        }

        // In-memory storage for verification codes (replace with database/cache in production)
        private static Dictionary<string, (string code, DateTime expires)> _verificationCodes;

        private async Task<string> GetAccessTokenAsync()
        {
            // Placeholder: Replace with your actual logic to retrieve the access token from the user context/session
            return await Task.FromResult(_httpContextAccessor.HttpContext.User.FindFirst("access_token")?.Value);
        }

        

        

    }
} 
