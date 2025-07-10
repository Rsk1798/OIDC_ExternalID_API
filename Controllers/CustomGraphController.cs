using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Configuration;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text.Json;
using System.Security.Claims;
using System.Text;

namespace OIDC_ExternalID_API.Controllers
{
    [ApiController]
    [Route("[controller]")]
    [Authorize]
    public class CustomGraphController : ControllerBase
    {
        private readonly IConfiguration _config;
        private readonly IHttpClientFactory _httpClientFactory;
        private readonly ILogger<CustomGraphController> _logger;

        public CustomGraphController(IConfiguration config, IHttpClientFactory httpClientFactory, ILogger<CustomGraphController> logger)
        {
            _config = config;
            _httpClientFactory = httpClientFactory;
            _logger = logger;
        }

        /// <summary>
        /// Get current user information from the JWT token
        /// </summary>
        [HttpGet("me")]
        public IActionResult GetCurrentUser()
        {
            try
            {
                var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
                var username = User.FindFirst(ClaimTypes.Name)?.Value;
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

        /// <summary>
        /// Get user by ID or email using your JWT token to authenticate with Microsoft Graph
        /// </summary>
        [HttpGet("getUserById")]
        public async Task<IActionResult> GetUser([FromQuery] string idOrEmail)
        {
            try
            {
                // Get the current user's JWT token from the request
                var authHeader = Request.Headers["Authorization"].FirstOrDefault();
                if (string.IsNullOrEmpty(authHeader) || !authHeader.StartsWith("Bearer "))
                {
                    return Unauthorized("Bearer token is required");
                }

                var jwtToken = authHeader.Substring("Bearer ".Length);

                // Use the JWT token to get an Azure AD access token for Microsoft Graph
                var graphToken = await GetMicrosoftGraphToken(jwtToken);
                if (string.IsNullOrEmpty(graphToken))
                {
                    return Unauthorized("Failed to obtain Microsoft Graph token");
                }

                // Call Microsoft Graph API directly
                using var client = _httpClientFactory.CreateClient();
                client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", graphToken);

                var response = await client.GetAsync($"https://graph.microsoft.com/v1.0/users/{idOrEmail}");
                
                if (response.IsSuccessStatusCode)
                {
                    var content = await response.Content.ReadAsStringAsync();
                    var userData = JsonDocument.Parse(content);
                    return Ok(userData.RootElement);
                }
                else
                {
                    var errorContent = await response.Content.ReadAsStringAsync();
                    _logger.LogError($"Microsoft Graph API error: {response.StatusCode} - {errorContent}");
                    return StatusCode((int)response.StatusCode, $"Graph API error: {errorContent}");
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting user by ID: {IdOrEmail}", idOrEmail);
                return StatusCode(500, $"Internal server error: {ex.Message}");
            }
        }

        /// <summary>
        /// Get user by email using your JWT token to authenticate with Microsoft Graph
        /// </summary>
        [HttpGet("getUserByEmail")]
        public async Task<IActionResult> GetUserByEmail([FromQuery] string email)
        {
            try
            {
                var authHeader = Request.Headers["Authorization"].FirstOrDefault();
                if (string.IsNullOrEmpty(authHeader) || !authHeader.StartsWith("Bearer "))
                {
                    return Unauthorized("Bearer token is required");
                }

                var jwtToken = authHeader.Substring("Bearer ".Length);
                var graphToken = await GetMicrosoftGraphToken(jwtToken);
                
                if (string.IsNullOrEmpty(graphToken))
                {
                    return Unauthorized("Failed to obtain Microsoft Graph token");
                }

                using var client = _httpClientFactory.CreateClient();
                client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", graphToken);

                // Use filter to find user by email
                var response = await client.GetAsync($"https://graph.microsoft.com/v1.0/users?$filter=mail eq '{email}' or otherMails/any(x:x eq '{email}')");
                
                if (response.IsSuccessStatusCode)
                {
                    var content = await response.Content.ReadAsStringAsync();
                    var usersData = JsonDocument.Parse(content);
                    var users = usersData.RootElement.GetProperty("value");
                    
                    if (users.GetArrayLength() > 0)
                    {
                        return Ok(users[0]);
                    }
                    else
                    {
                        return NotFound("User not found");
                    }
                }
                else
                {
                    var errorContent = await response.Content.ReadAsStringAsync();
                    return StatusCode((int)response.StatusCode, $"Graph API error: {errorContent}");
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting user by email: {Email}", email);
                return StatusCode(500, $"Internal server error: {ex.Message}");
            }
        }

        /// <summary>
        /// Update user by ID using your JWT token to authenticate with Microsoft Graph
        /// </summary>
        [HttpPatch("updateUserById")]
        public async Task<IActionResult> UpdateUser([FromQuery] string idOrEmail, [FromBody] JsonElement updates)
        {
            try
            {
                var authHeader = Request.Headers["Authorization"].FirstOrDefault();
                if (string.IsNullOrEmpty(authHeader) || !authHeader.StartsWith("Bearer "))
                {
                    return Unauthorized("Bearer token is required");
                }

                var jwtToken = authHeader.Substring("Bearer ".Length);
                var graphToken = await GetMicrosoftGraphToken(jwtToken);
                
                if (string.IsNullOrEmpty(graphToken))
                {
                    return Unauthorized("Failed to obtain Microsoft Graph token");
                }

                using var client = _httpClientFactory.CreateClient();
                client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", graphToken);

                var jsonContent = new StringContent(updates.GetRawText(), Encoding.UTF8, "application/json");
                var response = await client.PatchAsync($"https://graph.microsoft.com/v1.0/users/{idOrEmail}", jsonContent);
                
                if (response.IsSuccessStatusCode)
                {
                    return Ok("User updated successfully");
                }
                else
                {
                    var errorContent = await response.Content.ReadAsStringAsync();
                    return StatusCode((int)response.StatusCode, $"Graph API error: {errorContent}");
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error updating user: {IdOrEmail}", idOrEmail);
                return StatusCode(500, $"Internal server error: {ex.Message}");
            }
        }

        /// <summary>
        /// Update user by email using your JWT token to authenticate with Microsoft Graph
        /// </summary>
        [HttpPatch("updateUserByEmail")]
        public async Task<IActionResult> UpdateUserByEmail([FromQuery] string email, [FromBody] JsonElement updates)
        {
            try
            {
                var authHeader = Request.Headers["Authorization"].FirstOrDefault();
                if (string.IsNullOrEmpty(authHeader) || !authHeader.StartsWith("Bearer "))
                {
                    return Unauthorized("Bearer token is required");
                }

                var jwtToken = authHeader.Substring("Bearer ".Length);
                var graphToken = await GetMicrosoftGraphToken(jwtToken);
                
                if (string.IsNullOrEmpty(graphToken))
                {
                    return Unauthorized("Failed to obtain Microsoft Graph token");
                }

                using var client = _httpClientFactory.CreateClient();
                client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", graphToken);

                // First, find the user by email
                var searchResponse = await client.GetAsync($"https://graph.microsoft.com/v1.0/users?$filter=mail eq '{email}' or otherMails/any(x:x eq '{email}')");
                
                if (!searchResponse.IsSuccessStatusCode)
                {
                    var errorContent = await searchResponse.Content.ReadAsStringAsync();
                    return StatusCode((int)searchResponse.StatusCode, $"Graph API error: {errorContent}");
                }

                var searchContent = await searchResponse.Content.ReadAsStringAsync();
                var searchData = JsonDocument.Parse(searchContent);
                var users = searchData.RootElement.GetProperty("value");
                
                if (users.GetArrayLength() == 0)
                {
                    return NotFound("User not found");
                }

                var userId = users[0].GetProperty("id").GetString();

                // Update the user
                var jsonContent = new StringContent(updates.GetRawText(), Encoding.UTF8, "application/json");
                var updateResponse = await client.PatchAsync($"https://graph.microsoft.com/v1.0/users/{userId}", jsonContent);
                
                if (updateResponse.IsSuccessStatusCode)
                {
                    return Ok($"User with email '{email}' updated successfully");
                }
                else
                {
                    var errorContent = await updateResponse.Content.ReadAsStringAsync();
                    return StatusCode((int)updateResponse.StatusCode, $"Graph API error: {errorContent}");
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error updating user by email: {Email}", email);
                return StatusCode(500, $"Internal server error: {ex.Message}");
            }
        }

        /// <summary>
        /// Update user attributes by ID using your JWT token to authenticate with Microsoft Graph
        /// </summary>
        [HttpPatch("updateUserAttributesById")]
        public async Task<IActionResult> UpdateUserAttributesById([FromQuery] string idOrEmail, [FromBody] JsonElement updates)
        {
            try
            {
                var authHeader = Request.Headers["Authorization"].FirstOrDefault();
                if (string.IsNullOrEmpty(authHeader) || !authHeader.StartsWith("Bearer "))
                {
                    return Unauthorized("Bearer token is required");
                }

                var jwtToken = authHeader.Substring("Bearer ".Length);
                var graphToken = await GetMicrosoftGraphToken(jwtToken);
                
                if (string.IsNullOrEmpty(graphToken))
                {
                    return Unauthorized("Failed to obtain Microsoft Graph token");
                }

                using var client = _httpClientFactory.CreateClient();
                client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", graphToken);

                var jsonContent = new StringContent(updates.GetRawText(), Encoding.UTF8, "application/json");
                var response = await client.PatchAsync($"https://graph.microsoft.com/v1.0/users/{idOrEmail}", jsonContent);
                
                if (response.IsSuccessStatusCode)
                {
                    return Ok("User updated with limited attributes");
                }
                else
                {
                    var errorContent = await response.Content.ReadAsStringAsync();
                    return StatusCode((int)response.StatusCode, $"Graph API error: {errorContent}");
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error updating user attributes: {IdOrEmail}", idOrEmail);
                return StatusCode(500, $"Internal server error: {ex.Message}");
            }
        }

        /// <summary>
        /// Update user attributes by email using your JWT token to authenticate with Microsoft Graph
        /// </summary>
        [HttpPatch("updateUserAttributesByEmail")]
        public async Task<IActionResult> UpdateUserAttributesByEmail([FromQuery] string email, [FromBody] JsonElement updates)
        {
            try
            {
                var authHeader = Request.Headers["Authorization"].FirstOrDefault();
                if (string.IsNullOrEmpty(authHeader) || !authHeader.StartsWith("Bearer "))
                {
                    return Unauthorized("Bearer token is required");
                }

                var jwtToken = authHeader.Substring("Bearer ".Length);
                var graphToken = await GetMicrosoftGraphToken(jwtToken);
                
                if (string.IsNullOrEmpty(graphToken))
                {
                    return Unauthorized("Failed to obtain Microsoft Graph token");
                }

                using var client = _httpClientFactory.CreateClient();
                client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", graphToken);

                // First, find the user by email
                var searchResponse = await client.GetAsync($"https://graph.microsoft.com/v1.0/users?$filter=mail eq '{email}' or otherMails/any(x:x eq '{email}')");
                
                if (!searchResponse.IsSuccessStatusCode)
                {
                    var errorContent = await searchResponse.Content.ReadAsStringAsync();
                    return StatusCode((int)searchResponse.StatusCode, $"Graph API error: {errorContent}");
                }

                var searchContent = await searchResponse.Content.ReadAsStringAsync();
                var searchData = JsonDocument.Parse(searchContent);
                var users = searchData.RootElement.GetProperty("value");
                
                if (users.GetArrayLength() == 0)
                {
                    return NotFound("User not found");
                }

                var userId = users[0].GetProperty("id").GetString();

                // Update the user attributes
                var jsonContent = new StringContent(updates.GetRawText(), Encoding.UTF8, "application/json");
                var updateResponse = await client.PatchAsync($"https://graph.microsoft.com/v1.0/users/{userId}", jsonContent);
                
                if (updateResponse.IsSuccessStatusCode)
                {
                    return Ok($"User with email '{email}' updated with limited attributes");
                }
                else
                {
                    var errorContent = await updateResponse.Content.ReadAsStringAsync();
                    return StatusCode((int)updateResponse.StatusCode, $"Graph API error: {errorContent}");
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error updating user attributes by email: {Email}", email);
                return StatusCode(500, $"Internal server error: {ex.Message}");
            }
        }

        /// <summary>
        /// Delete user by ID using your JWT token to authenticate with Microsoft Graph
        /// </summary>
        [HttpDelete("deleteUserById")]
        public async Task<IActionResult> DeleteUser([FromQuery] string idOrEmail)
        {
            try
            {
                var authHeader = Request.Headers["Authorization"].FirstOrDefault();
                if (string.IsNullOrEmpty(authHeader) || !authHeader.StartsWith("Bearer "))
                {
                    return Unauthorized("Bearer token is required");
                }

                var jwtToken = authHeader.Substring("Bearer ".Length);
                var graphToken = await GetMicrosoftGraphToken(jwtToken);
                
                if (string.IsNullOrEmpty(graphToken))
                {
                    return Unauthorized("Failed to obtain Microsoft Graph token");
                }

                using var client = _httpClientFactory.CreateClient();
                client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", graphToken);

                var response = await client.DeleteAsync($"https://graph.microsoft.com/v1.0/users/{idOrEmail}");
                
                if (response.IsSuccessStatusCode)
                {
                    return Ok("User deleted successfully");
                }
                else
                {
                    var errorContent = await response.Content.ReadAsStringAsync();
                    return StatusCode((int)response.StatusCode, $"Graph API error: {errorContent}");
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error deleting user: {IdOrEmail}", idOrEmail);
                return StatusCode(500, $"Internal server error: {ex.Message}");
            }
        }

        /// <summary>
        /// Delete user by email using your JWT token to authenticate with Microsoft Graph
        /// </summary>
        [HttpDelete("deleteUserByEmail")]
        public async Task<IActionResult> DeleteUserByEmail([FromQuery] string email)
        {
            try
            {
                var authHeader = Request.Headers["Authorization"].FirstOrDefault();
                if (string.IsNullOrEmpty(authHeader) || !authHeader.StartsWith("Bearer "))
                {
                    return Unauthorized("Bearer token is required");
                }

                var jwtToken = authHeader.Substring("Bearer ".Length);
                var graphToken = await GetMicrosoftGraphToken(jwtToken);
                
                if (string.IsNullOrEmpty(graphToken))
                {
                    return Unauthorized("Failed to obtain Microsoft Graph token");
                }

                using var client = _httpClientFactory.CreateClient();
                client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", graphToken);

                // First, find the user by email
                var searchResponse = await client.GetAsync($"https://graph.microsoft.com/v1.0/users?$filter=mail eq '{email}' or otherMails/any(x:x eq '{email}')");
                
                if (!searchResponse.IsSuccessStatusCode)
                {
                    var errorContent = await searchResponse.Content.ReadAsStringAsync();
                    return StatusCode((int)searchResponse.StatusCode, $"Graph API error: {errorContent}");
                }

                var searchContent = await searchResponse.Content.ReadAsStringAsync();
                var searchData = JsonDocument.Parse(searchContent);
                var users = searchData.RootElement.GetProperty("value");
                
                if (users.GetArrayLength() == 0)
                {
                    return NotFound("User not found");
                }

                var userId = users[0].GetProperty("id").GetString();

                // Delete the user
                var deleteResponse = await client.DeleteAsync($"https://graph.microsoft.com/v1.0/users/{userId}");
                
                if (deleteResponse.IsSuccessStatusCode)
                {
                    return Ok($"User with email '{email}' deleted successfully");
                }
                else
                {
                    var errorContent = await deleteResponse.Content.ReadAsStringAsync();
                    return StatusCode((int)deleteResponse.StatusCode, $"Graph API error: {errorContent}");
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error deleting user by email: {Email}", email);
                return StatusCode(500, $"Internal server error: {ex.Message}");
            }
        }

        /// <summary>
        /// Change password using your JWT token to authenticate with Microsoft Graph
        /// </summary>
        [HttpPost("changePassword")]
        public async Task<IActionResult> ChangePassword([FromBody] JsonElement passwordChange)
        {
            try
            {
                var authHeader = Request.Headers["Authorization"].FirstOrDefault();
                if (string.IsNullOrEmpty(authHeader) || !authHeader.StartsWith("Bearer "))
                {
                    return Unauthorized("Bearer token is required");
                }

                var jwtToken = authHeader.Substring("Bearer ".Length);
                var graphToken = await GetMicrosoftGraphToken(jwtToken);
                
                if (string.IsNullOrEmpty(graphToken))
                {
                    return Unauthorized("Failed to obtain Microsoft Graph token");
                }

                using var client = _httpClientFactory.CreateClient();
                client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", graphToken);

                // Get current user ID from token
                var currentUserId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
                if (string.IsNullOrEmpty(currentUserId))
                {
                    return BadRequest("Unable to determine current user");
                }

                var jsonContent = new StringContent(passwordChange.GetRawText(), Encoding.UTF8, "application/json");
                var response = await client.PostAsync($"https://graph.microsoft.com/v1.0/users/{currentUserId}/changePassword", jsonContent);
                
                if (response.IsSuccessStatusCode)
                {
                    return Ok("Password changed successfully");
                }
                else
                {
                    var errorContent = await response.Content.ReadAsStringAsync();
                    return StatusCode((int)response.StatusCode, $"Graph API error: {errorContent}");
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error changing password");
                return StatusCode(500, $"Internal server error: {ex.Message}");
            }
        }

        /// <summary>
        /// Reset password by ID using your JWT token to authenticate with Microsoft Graph
        /// </summary>
        [HttpPatch("resetPasswordById")]
        public async Task<IActionResult> ResetPasswordById([FromQuery] string idOrEmail, [FromBody] JsonElement passwordReset)
        {
            try
            {
                var authHeader = Request.Headers["Authorization"].FirstOrDefault();
                if (string.IsNullOrEmpty(authHeader) || !authHeader.StartsWith("Bearer "))
                {
                    return Unauthorized("Bearer token is required");
                }

                var jwtToken = authHeader.Substring("Bearer ".Length);
                var graphToken = await GetMicrosoftGraphToken(jwtToken);
                
                if (string.IsNullOrEmpty(graphToken))
                {
                    return Unauthorized("Failed to obtain Microsoft Graph token");
                }

                using var client = _httpClientFactory.CreateClient();
                client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", graphToken);

                var jsonContent = new StringContent(passwordReset.GetRawText(), Encoding.UTF8, "application/json");
                var response = await client.PatchAsync($"https://graph.microsoft.com/v1.0/users/{idOrEmail}", jsonContent);
                
                if (response.IsSuccessStatusCode)
                {
                    return Ok($"Password reset successfully for user {idOrEmail}");
                }
                else
                {
                    var errorContent = await response.Content.ReadAsStringAsync();
                    return StatusCode((int)response.StatusCode, $"Graph API error: {errorContent}");
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error resetting password: {IdOrEmail}", idOrEmail);
                return StatusCode(500, $"Internal server error: {ex.Message}");
            }
        }

        /// <summary>
        /// Reset password by email using your JWT token to authenticate with Microsoft Graph
        /// </summary>
        [HttpPatch("resetPasswordByEmail")]
        public async Task<IActionResult> ResetPasswordByEmail([FromQuery] string email, [FromBody] JsonElement passwordReset)
        {
            try
            {
                var authHeader = Request.Headers["Authorization"].FirstOrDefault();
                if (string.IsNullOrEmpty(authHeader) || !authHeader.StartsWith("Bearer "))
                {
                    return Unauthorized("Bearer token is required");
                }

                var jwtToken = authHeader.Substring("Bearer ".Length);
                var graphToken = await GetMicrosoftGraphToken(jwtToken);
                
                if (string.IsNullOrEmpty(graphToken))
                {
                    return Unauthorized("Failed to obtain Microsoft Graph token");
                }

                using var client = _httpClientFactory.CreateClient();
                client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", graphToken);

                // First, find the user by email
                var searchResponse = await client.GetAsync($"https://graph.microsoft.com/v1.0/users?$filter=mail eq '{email}' or otherMails/any(x:x eq '{email}')");
                
                if (!searchResponse.IsSuccessStatusCode)
                {
                    var errorContent = await searchResponse.Content.ReadAsStringAsync();
                    return StatusCode((int)searchResponse.StatusCode, $"Graph API error: {errorContent}");
                }

                var searchContent = await searchResponse.Content.ReadAsStringAsync();
                var searchData = JsonDocument.Parse(searchContent);
                var users = searchData.RootElement.GetProperty("value");
                
                if (users.GetArrayLength() == 0)
                {
                    return NotFound("User not found");
                }

                var userId = users[0].GetProperty("id").GetString();

                // Reset the password
                var jsonContent = new StringContent(passwordReset.GetRawText(), Encoding.UTF8, "application/json");
                var resetResponse = await client.PatchAsync($"https://graph.microsoft.com/v1.0/users/{userId}", jsonContent);
                
                if (resetResponse.IsSuccessStatusCode)
                {
                    return Ok($"Password reset successfully for user with email '{email}'");
                }
                else
                {
                    var errorContent = await resetResponse.Content.ReadAsStringAsync();
                    return StatusCode((int)resetResponse.StatusCode, $"Graph API error: {errorContent}");
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error resetting password by email: {Email}", email);
                return StatusCode(500, $"Internal server error: {ex.Message}");
            }
        }

        /// <summary>
        /// Get all users using your JWT token to authenticate with Microsoft Graph
        /// </summary>
        [HttpGet("getAllUsers")]
        public async Task<IActionResult> GetAllUsers([FromQuery] int? top = 10)
        {
            try
            {
                var authHeader = Request.Headers["Authorization"].FirstOrDefault();
                if (string.IsNullOrEmpty(authHeader) || !authHeader.StartsWith("Bearer "))
                {
                    return Unauthorized("Bearer token is required");
                }

                var jwtToken = authHeader.Substring("Bearer ".Length);
                var graphToken = await GetMicrosoftGraphToken(jwtToken);
                
                if (string.IsNullOrEmpty(graphToken))
                {
                    return Unauthorized("Failed to obtain Microsoft Graph token");
                }

                using var client = _httpClientFactory.CreateClient();
                client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", graphToken);

                var url = $"https://graph.microsoft.com/v1.0/users?$top={top}";
                var response = await client.GetAsync(url);
                
                if (response.IsSuccessStatusCode)
                {
                    var content = await response.Content.ReadAsStringAsync();
                    var usersData = JsonDocument.Parse(content);
                    return Ok(usersData.RootElement);
                }
                else
                {
                    var errorContent = await response.Content.ReadAsStringAsync();
                    return StatusCode((int)response.StatusCode, $"Graph API error: {errorContent}");
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting all users");
                return StatusCode(500, $"Internal server error: {ex.Message}");
            }
        }

        /// <summary>
        /// Exchange your JWT token for a Microsoft Graph access token
        /// This is where you can implement your own token exchange logic
        /// </summary>
        private async Task<string> GetMicrosoftGraphToken(string jwtToken)
        {
            try
            {
                // Option 1: Use your JWT token directly (if it has the right claims/scopes)
                // This would require your JWT token to be accepted by Microsoft Graph
                
                // Option 2: Exchange your JWT token for an Azure AD token
                // This is the more common approach
                
                var tenantId = _config["AzureAd:TenantId"];
                var clientId = _config["AzureAd:ClientId"];
                var clientSecret = _config["AzureAd:ClientSecret"];

                using var client = _httpClientFactory.CreateClient();
                
                // Use client credentials flow to get Microsoft Graph token
                var tokenRequest = new FormUrlEncodedContent(new[]
                {
                    new KeyValuePair<string, string>("grant_type", "client_credentials"),
                    new KeyValuePair<string, string>("client_id", clientId),
                    new KeyValuePair<string, string>("client_secret", clientSecret),
                    new KeyValuePair<string, string>("scope", "https://graph.microsoft.com/.default")
                });

                var tokenResponse = await client.PostAsync($"https://login.microsoftonline.com/{tenantId}/oauth2/v2.0/token", tokenRequest);
                
                if (tokenResponse.IsSuccessStatusCode)
                {
                    var tokenContent = await tokenResponse.Content.ReadAsStringAsync();
                    var tokenData = JsonDocument.Parse(tokenContent);
                    return tokenData.RootElement.GetProperty("access_token").GetString();
                }
                else
                {
                    _logger.LogError("Failed to get Microsoft Graph token: {StatusCode}", tokenResponse.StatusCode);
                    return null;
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting Microsoft Graph token");
                return null;
            }
        }
    }
} 