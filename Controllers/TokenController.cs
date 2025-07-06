using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;
using System.Net.Http;
using System.Threading.Tasks;
using System.Collections.Generic;
using System.Text.Json;
using Microsoft.Graph;
using Microsoft.Extensions.Configuration;
using System.Web;
using System.Linq;

namespace OIDC_ExternalID_API.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class TokenController : ControllerBase
    {
        private readonly IConfiguration _config;
        private readonly GraphServiceClient _graphServiceClient;

        public TokenController(IConfiguration config, GraphServiceClient graphServiceClient)
        {
            _config = config;
            _graphServiceClient = graphServiceClient;
        }

        // Step 1: Request authorization - Redirect user to Microsoft login
        [HttpGet("authorize")]
        [AllowAnonymous]
        public IActionResult Authorize([FromQuery] string redirectUri = null, [FromQuery] string state = null)
        {
            var tenantId = _config["AzureAd:TenantId"];
            var clientId = _config["AzureAd:ClientId"];
            
            // Default redirect URI if not provided
            if (string.IsNullOrEmpty(redirectUri))
            {
                redirectUri = $"{Request.Scheme}://{Request.Host}/Token/callback";
            }

            // Generate state parameter if not provided
            if (string.IsNullOrEmpty(state))
            {
                state = Guid.NewGuid().ToString();
            }

            // Store state in session or cache for validation
            HttpContext.Session.SetString("auth_state", state);

            // Build authorization URL as per Microsoft documentation
            var authUrl = $"https://login.microsoftonline.com/{tenantId}/oauth2/v2.0/authorize?" +
                         $"client_id={clientId}" +
                         $"&response_type=code" +
                         $"&redirect_uri={HttpUtility.UrlEncode(redirectUri)}" +
                         $"&response_mode=query" +
                         $"&scope={HttpUtility.UrlEncode("offline_access Directory.AccessAsUser.All User.Read")}" +
                         $"&state={state}";

            return Redirect(authUrl);
        }

        // Step 2: Handle authorization callback and exchange code for token
        [HttpGet("callback")]
        [AllowAnonymous]
        public async Task<IActionResult> Callback([FromQuery] string code, [FromQuery] string state, [FromQuery] string error = null)
        {
            if (!string.IsNullOrEmpty(error))
            {
                return BadRequest($"Authorization failed: {error}");
            }

            if (string.IsNullOrEmpty(code))
            {
                return BadRequest("Authorization code is required");
            }

            // Validate state parameter
            var storedState = HttpContext.Session.GetString("auth_state");
            if (string.IsNullOrEmpty(storedState) || storedState != state)
            {
                return BadRequest("Invalid state parameter");
            }

            // Clear the state from session
            HttpContext.Session.Remove("auth_state");

            try
            {
                // Exchange authorization code for access token
                var tokenResponse = await ExchangeCodeForToken(code);
                return Ok(tokenResponse);
            }
            catch (Exception ex)
            {
                return BadRequest($"Token exchange failed: {ex.Message}");
            }
        }

        // Step 3: Exchange authorization code for access token
        private async Task<object> ExchangeCodeForToken(string authorizationCode)
        {
            var tenantId = _config["AzureAd:TenantId"];
            var clientId = _config["AzureAd:ClientId"];
            var clientSecret = _config["AzureAd:ClientSecret"];
            var redirectUri = $"{Request.Scheme}://{Request.Host}/Token/callback";

            using var client = new HttpClient();
            var parameters = new Dictionary<string, string>
            {
                {"client_id", clientId},
                {"scope", "Directory.AccessAsUser.All User.Read"},
                {"code", authorizationCode},
                {"redirect_uri", redirectUri},
                {"grant_type", "authorization_code"},
                {"client_secret", clientSecret}
            };

            var content = new FormUrlEncodedContent(parameters);
            var response = await client.PostAsync($"https://login.microsoftonline.com/{tenantId}/oauth2/v2.0/token", content);
            var responseString = await response.Content.ReadAsStringAsync();

            if (!response.IsSuccessStatusCode)
            {
                throw new Exception($"Token exchange failed: {responseString}");
            }

            var json = JsonDocument.Parse(responseString);
            return new
            {
                access_token = json.RootElement.GetProperty("access_token").GetString(),
                refresh_token = json.RootElement.TryGetProperty("refresh_token", out var refreshToken) ? refreshToken.GetString() : null,
                expires_in = json.RootElement.GetProperty("expires_in").GetInt32(),
                token_type = json.RootElement.GetProperty("token_type").GetString(),
                scope = json.RootElement.GetProperty("scope").GetString()
            };
        }

        // Step 4: Refresh access token using refresh token
        [HttpPost("refresh")]
        [AllowAnonymous]
        public async Task<IActionResult> RefreshToken([FromBody] RefreshTokenRequest request)
        {
            if (string.IsNullOrEmpty(request.RefreshToken))
            {
                return BadRequest("Refresh token is required");
            }

            try
            {
                var tenantId = _config["AzureAd:TenantId"];
                var clientId = _config["AzureAd:ClientId"];
                var clientSecret = _config["AzureAd:ClientSecret"];

                using var client = new HttpClient();
                var parameters = new Dictionary<string, string>
                {
                    {"client_id", clientId},
                    {"scope", "Directory.AccessAsUser.All User.Read"},
                    {"refresh_token", request.RefreshToken},
                    {"grant_type", "refresh_token"},
                    {"client_secret", clientSecret}
                };

                var content = new FormUrlEncodedContent(parameters);
                var response = await client.PostAsync($"https://login.microsoftonline.com/{tenantId}/oauth2/v2.0/token", content);
                var responseString = await response.Content.ReadAsStringAsync();

                if (!response.IsSuccessStatusCode)
                {
                    return BadRequest($"Token refresh failed: {responseString}");
                }

                var json = JsonDocument.Parse(responseString);
                return Ok(new
                {
                    access_token = json.RootElement.GetProperty("access_token").GetString(),
                    refresh_token = json.RootElement.TryGetProperty("refresh_token", out var refreshToken) ? refreshToken.GetString() : null,
                    expires_in = json.RootElement.GetProperty("expires_in").GetInt32(),
                    token_type = json.RootElement.GetProperty("token_type").GetString(),
                    scope = json.RootElement.GetProperty("scope").GetString()
                });
            }
            catch (Exception ex)
            {
                return BadRequest($"Token refresh failed: {ex.Message}");
            }
        }

        // Step 1: Request admin consent for application permissions
        [HttpGet("adminconsent")]
        [AllowAnonymous]
        public IActionResult RequestAdminConsent([FromQuery] string redirectUri = null, [FromQuery] string state = null)
        {
            var tenantId = _config["AzureAd:TenantId"];
            var clientId = _config["AzureAd:ClientId"];
            
            // Default redirect URI if not provided
            if (string.IsNullOrEmpty(redirectUri))
            {
                redirectUri = $"{Request.Scheme}://{Request.Host}/Token/adminconsent-callback";
            }

            // Generate state parameter if not provided
            if (string.IsNullOrEmpty(state))
            {
                state = Guid.NewGuid().ToString();
            }

            // Store state in session for validation
            HttpContext.Session.SetString("adminconsent_state", state);

            // Build admin consent URL as per Microsoft documentation
            var adminConsentUrl = $"https://login.microsoftonline.com/{tenantId}/adminconsent?" +
                                 $"client_id={clientId}" +
                                 $"&state={state}" +
                                 $"&redirect_uri={HttpUtility.UrlEncode(redirectUri)}";

            return Redirect(adminConsentUrl);
        }

        // Step 2: Handle admin consent callback
        [HttpGet("adminconsent-callback")]
        [AllowAnonymous]
        public IActionResult AdminConsentCallback([FromQuery] string admin_consent, [FromQuery] string tenant, [FromQuery] string state, [FromQuery] string error = null)
        {
            if (!string.IsNullOrEmpty(error))
            {
                return BadRequest($"Admin consent failed: {error}");
            }

            // Validate state parameter
            var storedState = HttpContext.Session.GetString("adminconsent_state");
            if (string.IsNullOrEmpty(storedState) || storedState != state)
            {
                return BadRequest("Invalid state parameter");
            }

            // Clear the state from session
            HttpContext.Session.Remove("adminconsent_state");

            if (admin_consent == "True")
            {
                return Ok(new
                {
                    success = true,
                    message = "Admin consent granted successfully",
                    tenant = tenant,
                    state = state
                });
            }
            else
            {
                return BadRequest("Admin consent was not granted");
            }
        }

        // Step 3: Get app-only token using client credentials flow
        [HttpPost("getAppOnlyToken")]
        [AllowAnonymous]
        public async Task<IActionResult> GetAppOnlyToken([FromQuery] string scope = null)
        {
            try
            {
                var tenantId = _config["AzureAd:TenantId"];
                var clientId = _config["AzureAd:ClientId"];
                var clientSecret = _config["AzureAd:ClientSecret"];

                // Use default scope if not provided
                if (string.IsNullOrEmpty(scope))
                {
                    scope = "https://graph.microsoft.com/.default";
                }

                using var client = new HttpClient();
                var parameters = new Dictionary<string, string>
                {
                    {"client_id", clientId},
                    {"scope", scope},
                    {"client_secret", clientSecret},
                    {"grant_type", "client_credentials"}
                };

                var content = new FormUrlEncodedContent(parameters);
                var response = await client.PostAsync($"https://login.microsoftonline.com/{tenantId}/oauth2/v2.0/token", content);
                var responseString = await response.Content.ReadAsStringAsync();

                if (!response.IsSuccessStatusCode)
                {
                    return BadRequest($"App-only token request failed: {responseString}");
                }

                var json = JsonDocument.Parse(responseString);
                return Ok(new
                {
                    access_token = json.RootElement.GetProperty("access_token").GetString(),
                    expires_in = json.RootElement.GetProperty("expires_in").GetInt32(),
                    ext_expires_in = json.RootElement.TryGetProperty("ext_expires_in", out var extExpires) ? extExpires.GetInt32() : (int?)null,
                    token_type = json.RootElement.GetProperty("token_type").GetString()
                });
            }
            catch (Exception ex)
            {
                return BadRequest($"App-only token request failed: {ex.Message}");
            }
        }

        // Step 4: Test app-only access by calling Microsoft Graph
        [HttpGet("testAppOnlyAccess")]
        [AllowAnonymous]
        public async Task<IActionResult> TestAppOnlyAccess([FromQuery] string accessToken)
        {
            if (string.IsNullOrEmpty(accessToken))
            {
                return BadRequest("Access token is required");
            }

            try
            {
                using var client = new HttpClient();
                client.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", accessToken);
                client.DefaultRequestHeaders.Accept.Add(new System.Net.Http.Headers.MediaTypeWithQualityHeaderValue("application/json"));

                // Test by calling Microsoft Graph to get users (requires User.Read.All permission)
                var response = await client.GetAsync("https://graph.microsoft.com/v1.0/users");
                var responseString = await response.Content.ReadAsStringAsync();

                if (response.IsSuccessStatusCode)
                {
                    var json = JsonDocument.Parse(responseString);
                    return Ok(new
                    {
                        success = true,
                        message = "App-only access test successful",
                        userCount = json.RootElement.GetProperty("value").GetArrayLength(),
                        sampleUsers = json.RootElement.GetProperty("value").EnumerateArray().Take(3).Select(u => new
                        {
                            id = u.GetProperty("id").GetString(),
                            displayName = u.GetProperty("displayName").GetString(),
                            userPrincipalName = u.GetProperty("userPrincipalName").GetString()
                        }).ToList()
                    });
                }
                else
                {
                    return BadRequest($"Graph API call failed: {responseString}");
                }
            }
            catch (Exception ex)
            {
                return BadRequest($"App-only access test failed: {ex.Message}");
            }
        }

        // Legacy ROPC endpoint (kept for backward compatibility)
        [HttpPost("getTestToken")]
        [AllowAnonymous]
        public async Task<IActionResult> GetTestToken([FromBody] TokenRequestModel model)
        {
            if (string.IsNullOrEmpty(model.Password))
                return BadRequest("Password is required.");

            if (string.IsNullOrEmpty(model.Email))
                return BadRequest("Email is required.");

            // Lookup by email
            var users = await _graphServiceClient.Users
                .GetAsync(requestConfig =>
                {
                    requestConfig.QueryParameters.Filter = $"mail eq '{model.Email}' or otherMails/any(x:x eq '{model.Email}')";
                });
            var user = users?.Value?.FirstOrDefault();
            if (user == null)
                return BadRequest("User not found for the provided email.");
            var upn = user.UserPrincipalName;

            var tenantId = _config["AzureAd:TenantId"];
            var clientId = _config["AzureAd:ClientId"];
            var clientSecret = _config["AzureAd:ClientSecret"];
            var authority = $"https://login.microsoftonline.com/{tenantId}/oauth2/v2.0/token";

            using var client = new HttpClient();
            var parameters = new Dictionary<string, string>
            {
                {"client_id", clientId},
                {"scope", "https://graph.microsoft.com/.default"},
                {"username", upn},
                {"password", model.Password},
                {"grant_type", "password"},
                {"client_secret", clientSecret}
            };

            var content = new FormUrlEncodedContent(parameters);
            var response = await client.PostAsync(authority, content);
            var responseString = await response.Content.ReadAsStringAsync();

            if (!response.IsSuccessStatusCode)
                return BadRequest(responseString);

            var json = JsonDocument.Parse(responseString);
            var accessToken = json.RootElement.GetProperty("access_token").GetString();

            return Ok(new { access_token = accessToken });
        }

        [HttpPost("getAppToken")]
        [AllowAnonymous]
        public async Task<IActionResult> GetAppToken()
        {
            var tenantId = _config["AzureAd:TenantId"];
            var clientId = _config["AzureAd:ClientId"];
            var clientSecret = _config["AzureAd:ClientSecret"];
            var authority = $"https://login.microsoftonline.com/{tenantId}/oauth2/v2.0/token";

            using var client = new HttpClient();
            var parameters = new Dictionary<string, string>
            {
                {"client_id", clientId},
                {"scope", "https://graph.microsoft.com/.default"},
                {"client_secret", clientSecret},
                {"grant_type", "client_credentials"}
            };

            var content = new FormUrlEncodedContent(parameters);
            var response = await client.PostAsync(authority, content);
            var responseString = await response.Content.ReadAsStringAsync();

            if (!response.IsSuccessStatusCode)
                return BadRequest(responseString);

            var json = JsonDocument.Parse(responseString);
            var accessToken = json.RootElement.GetProperty("access_token").GetString();

            return Ok(new { access_token = accessToken });
        }
    }

    public class TokenRequestModel
    {
        public string Email { get; set; }
        public string Password { get; set; }
    }

    public class RefreshTokenRequest
    {
        public string RefreshToken { get; set; }
    }
} 