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
using Azure.Identity;
using System.ComponentModel;
using System.ComponentModel.DataAnnotations;

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

        // OAuth 2.0 Authorization Code Flow - For User Authentication
        [HttpGet("authorize")]
        [AllowAnonymous]
        [ApiExplorerSettings(IgnoreApi = true)]
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

            // Store state in session for validation
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

        [HttpGet("callback")]
        [AllowAnonymous]
        [ApiExplorerSettings(IgnoreApi = true)]
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

        [HttpPost("refresh")]
        [AllowAnonymous]
        [ApiExplorerSettings(IgnoreApi = true)]
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

        // Admin Consent Flow - For App-Only Access
        [HttpGet("adminconsent")]
        [AllowAnonymous]
        [ApiExplorerSettings(IgnoreApi = true)]
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

        [HttpGet("adminconsent-callback")]
        [AllowAnonymous]
        [ApiExplorerSettings(IgnoreApi = true)]
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

        // Unified Token Generation - Single Endpoint for All Token Types
        [HttpPost("generate")]
        [AllowAnonymous]
        [ApiExplorerSettings(IgnoreApi = true)]
        public async Task<IActionResult> GenerateToken([FromBody] TokenGenerationRequest request)
        {
            if (request == null)
            {
                return BadRequest("Request body is required");
            }

            try
            {
                var tenantId = _config["AzureAd:TenantId"];
                var clientId = _config["AzureAd:ClientId"];
                var clientSecret = _config["AzureAd:ClientSecret"];

                using var client = new HttpClient();

                switch (request.GrantType.ToLower())
                {
                    case "client_credentials":
                        return await GenerateAppOnlyToken(client, tenantId, clientId, clientSecret, request.Scope);
                    
                    case "password":
                        return await GenerateUserToken(client, tenantId, clientId, clientSecret, request.Username, request.Password, request.Scope);
                    
                    case "refresh_token":
                        return await RefreshUserToken(client, tenantId, clientId, clientSecret, request.RefreshToken, request.Scope);
                    
                    default:
                        return BadRequest($"Unsupported grant type: {request.GrantType}. Supported types: client_credentials, password, refresh_token");
                }
            }
            catch (Exception ex)
            {
                return BadRequest($"Token generation failed: {ex.Message}");
            }
        }

        private async Task<IActionResult> GenerateAppOnlyToken(HttpClient client, string tenantId, string clientId, string clientSecret, string scope = null)
        {
            if (string.IsNullOrEmpty(scope))
            {
                scope = "https://graph.microsoft.com/.default";
            }

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
                grant_type = "client_credentials",
                access_token = json.RootElement.GetProperty("access_token").GetString(),
                expires_in = json.RootElement.GetProperty("expires_in").GetInt32(),
                ext_expires_in = json.RootElement.TryGetProperty("ext_expires_in", out var extExpires) ? extExpires.GetInt32() : (int?)null,
                token_type = json.RootElement.GetProperty("token_type").GetString()
            });
        }

        private async Task<IActionResult> GenerateUserToken(HttpClient client, string tenantId, string clientId, string clientSecret, string username, string password, string scope = null)
        {
            if (string.IsNullOrEmpty(username) || string.IsNullOrEmpty(password))
            {
                return BadRequest("Username and password are required for password grant type");
            }

            if (string.IsNullOrEmpty(scope))
            {
                scope = "https://graph.microsoft.com/.default";
            }

            // Determine if username is email or UPN
            string upn = username;
            
            // If it looks like an email but not a UPN, try to look up the UPN
            if (username.Contains("@") && !username.EndsWith(".onmicrosoft.com"))
            {
                try
                {
                    // Use Graph API to look up the user and get their UPN
                    var graphClient = new GraphServiceClient(new ClientSecretCredential(tenantId, clientId, clientSecret), new[] { "https://graph.microsoft.com/.default" });
                    
                    var users = await graphClient.Users
                        .GetAsync(requestConfig =>
                        {
                            requestConfig.QueryParameters.Filter = $"mail eq '{username}' or otherMails/any(x:x eq '{username}')";
                        });

                    var user = users?.Value?.FirstOrDefault();
                    if (user != null && !string.IsNullOrEmpty(user.UserPrincipalName))
                    {
                        upn = user.UserPrincipalName;
                    }
                    else
                    {
                        return BadRequest($"User not found for email: {username}. Please use the User Principal Name (UPN) instead.");
                    }
                }
                catch (Exception ex)
                {
                    return BadRequest($"Unable to look up UPN for email {username}. Please use the User Principal Name (UPN) directly. Error: {ex.Message}");
                }
            }

            var parameters = new Dictionary<string, string>
            {
                {"client_id", clientId},
                {"scope", scope},
                {"username", upn},
                {"password", password},
                {"grant_type", "password"},
                {"client_secret", clientSecret}
            };

            var content = new FormUrlEncodedContent(parameters);
            var response = await client.PostAsync($"https://login.microsoftonline.com/{tenantId}/oauth2/v2.0/token", content);
            var responseString = await response.Content.ReadAsStringAsync();

            if (!response.IsSuccessStatusCode)
            {
                return BadRequest($"User token request failed: {responseString}");
            }

            var json = JsonDocument.Parse(responseString);
            return Ok(new
            {
                grant_type = "password",
                access_token = json.RootElement.GetProperty("access_token").GetString(),
                refresh_token = json.RootElement.TryGetProperty("refresh_token", out var refreshToken) ? refreshToken.GetString() : null,
                expires_in = json.RootElement.GetProperty("expires_in").GetInt32(),
                token_type = json.RootElement.GetProperty("token_type").GetString(),
                scope = json.RootElement.GetProperty("scope").GetString(),
                user_principal_name = upn
            });
        }

        private async Task<IActionResult> RefreshUserToken(HttpClient client, string tenantId, string clientId, string clientSecret, string refreshToken, string scope = null)
        {
            if (string.IsNullOrEmpty(refreshToken))
            {
                return BadRequest("Refresh token is required for refresh_token grant type");
            }

            if (string.IsNullOrEmpty(scope))
            {
                scope = "Directory.AccessAsUser.All User.Read";
            }

            var parameters = new Dictionary<string, string>
            {
                {"client_id", clientId},
                {"scope", scope},
                {"refresh_token", refreshToken},
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
                grant_type = "refresh_token",
                access_token = json.RootElement.GetProperty("access_token").GetString(),
                refresh_token = json.RootElement.TryGetProperty("refresh_token", out var newRefreshToken) ? newRefreshToken.GetString() : null,
                expires_in = json.RootElement.GetProperty("expires_in").GetInt32(),
                token_type = json.RootElement.GetProperty("token_type").GetString(),
                scope = json.RootElement.GetProperty("scope").GetString()
            });
        }

        // Test endpoint for app-only access
        [HttpGet("test")]
        [AllowAnonymous]
        [ApiExplorerSettings(IgnoreApi = true)]
        public async Task<IActionResult> TestAccess([FromQuery] string accessToken)
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
                        message = "Access test successful",
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
                return BadRequest($"Access test failed: {ex.Message}");
            }
        }


        // Legacy ROPC endpoint (kept for backward compatibility)
        [HttpPost("getTestToken")]
        [ApiExplorerSettings(IgnoreApi = true)]
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
        [ApiExplorerSettings(IgnoreApi = true)]
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

        // OAuth 2.0 Client Credentials Flow - Similar to Postman Implementation
        [HttpPost("oauth2/client-credentials")]
        [AllowAnonymous]
        public async Task<IActionResult> OAuth2ClientCredentials([FromBody] OAuth2ClientCredentialsRequest request)
        {
            if (request == null)
            {
                return BadRequest("Request body is required");
            }

            try
            {
                var tenantId = request.TenantId ?? _config["AzureAd:TenantId"];
                var clientId = request.ClientId ?? _config["AzureAd:ClientId"];
                var clientSecret = request.ClientSecret ?? _config["AzureAd:ClientSecret"];
                var scope = request.Scope ?? "https://graph.microsoft.com/.default";

                // Validate required configuration
                if (string.IsNullOrEmpty(tenantId))
                {
                    return BadRequest("TenantId is not provided in request and AzureAd:TenantId is not configured in appsettings.json");
                }
                if (string.IsNullOrEmpty(clientId))
                {
                    return BadRequest("ClientId is not provided in request and AzureAd:ClientId is not configured in appsettings.json");
                }
                if (string.IsNullOrEmpty(clientSecret))
                {
                    return BadRequest("ClientSecret is not provided in request and AzureAd:ClientSecret is not configured in appsettings.json");
                }

                using var client = new HttpClient();
                var parameters = new Dictionary<string, string>
                {
                    {"grant_type", "client_credentials"},
                    {"client_id", clientId},
                    {"scope", scope}
                };

                // Add client secret based on authentication method
                if (request.ClientAuthentication == "basic_auth")
                {
                    // Send as Basic Auth header (like Postman)
                    var credentials = Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes($"{clientId}:{clientSecret}"));
                    client.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Basic", credentials);
                }
                else
                {
                    // Send in request body (default)
                    parameters.Add("client_secret", clientSecret);
                }

                var content = new FormUrlEncodedContent(parameters);
                var tokenUrl = $"https://login.microsoftonline.com/{tenantId}/oauth2/v2.0/token";
                
                var response = await client.PostAsync(tokenUrl, content);
                var responseString = await response.Content.ReadAsStringAsync();

                if (!response.IsSuccessStatusCode)
                {
                    return BadRequest($"OAuth 2.0 client credentials request failed: {responseString}");
                }

                // Parse JSON response with better error handling
                JsonDocument json;
                try
                {
                    json = JsonDocument.Parse(responseString);
                }
                catch (JsonException ex)
                {
                    return BadRequest($"OAuth 2.0 client credentials request failed: Invalid JSON response. Error: {ex.Message}. Response: {responseString}");
                }

                // Check for required properties with better error messages
                if (!json.RootElement.TryGetProperty("access_token", out var accessTokenElement))
                {
                    return BadRequest($"OAuth 2.0 client credentials request failed: Missing 'access_token' in response. Available properties: {string.Join(", ", json.RootElement.EnumerateObject().Select(p => p.Name))}. Full response: {responseString}");
                }

                if (!json.RootElement.TryGetProperty("expires_in", out var expiresInElement))
                {
                    return BadRequest($"OAuth 2.0 client credentials request failed: Missing 'expires_in' in response. Available properties: {string.Join(", ", json.RootElement.EnumerateObject().Select(p => p.Name))}. Full response: {responseString}");
                }

                if (!json.RootElement.TryGetProperty("token_type", out var tokenTypeElement))
                {
                    return BadRequest($"OAuth 2.0 client credentials request failed: Missing 'token_type' in response. Available properties: {string.Join(", ", json.RootElement.EnumerateObject().Select(p => p.Name))}. Full response: {responseString}");
                }

                // Scope is optional in client credentials flow
                var scopeValue = json.RootElement.TryGetProperty("scope", out var scopeElement) ? scopeElement.GetString() : scope;

                return Ok(new
                {
                    token_name = request.TokenName ?? "GraphToken",
                    grant_type = "client_credentials",
                    access_token = accessTokenElement.GetString(),
                    expires_in = expiresInElement.GetInt32(),
                    ext_expires_in = json.RootElement.TryGetProperty("ext_expires_in", out var extExpires) ? extExpires.GetInt32() : (int?)null,
                    token_type = tokenTypeElement.GetString(),
                    scope = scopeValue,
                    tenant_id = tenantId,
                    client_id = clientId,
                    client_authentication = request.ClientAuthentication ?? "body",
                    debug_info = new
                    {
                        request_url = tokenUrl,
                        request_parameters = parameters,
                        response_status = (int)response.StatusCode,
                        response_headers = response.Headers.ToDictionary(h => h.Key, h => h.Value),
                        available_properties = json.RootElement.EnumerateObject().Select(p => p.Name).ToArray()
                    }
                });
            }
            catch (Exception ex)
            {
                return BadRequest($"OAuth 2.0 client credentials request failed: {ex.Message}. Stack trace: {ex.StackTrace}");
            }
        }

        // OAuth 2.0 Authorization Code Flow - Similar to Postman Implementation
        [HttpPost("oauth2/authorization-code")]
        [AllowAnonymous]
        [ApiExplorerSettings(IgnoreApi = true)]
        public async Task<IActionResult> OAuth2AuthorizationCode([FromBody] OAuth2AuthorizationCodeRequest request)
        {
            if (request == null)
            {
                return BadRequest("Request body is required");
            }

            if (string.IsNullOrEmpty(request.AuthorizationCode))
            {
                return BadRequest("Authorization code is required");
            }

            // Validate authorization code format
            if (request.AuthorizationCode.Length < 10)
            {
                return BadRequest("Authorization code appears to be too short. Please make sure you copied the entire code from the redirect URL.");
            }

            if (!request.AuthorizationCode.StartsWith("M.") && !request.AuthorizationCode.StartsWith("0."))
            {
                return BadRequest("Authorization code format appears invalid. Expected format: M.xxxxx... or 0.xxxxx...");
            }

            try
            {
                var tenantId = request.TenantId ?? _config["AzureAd:TenantId"];
                var clientId = request.ClientId ?? _config["AzureAd:ClientId"];
                var clientSecret = request.ClientSecret ?? _config["AzureAd:ClientSecret"];
                var redirectUri = request.RedirectUri ?? "https://oauth.pstmn.io/v1/callback";
                var scope = request.Scope ?? "https://graph.microsoft.com/.default";

                // Validate required configuration
                if (string.IsNullOrEmpty(tenantId))
                {
                    return BadRequest("TenantId is not provided in request and AzureAd:TenantId is not configured in appsettings.json");
                }
                if (string.IsNullOrEmpty(clientId))
                {
                    return BadRequest("ClientId is not provided in request and AzureAd:ClientId is not configured in appsettings.json");
                }
                if (string.IsNullOrEmpty(clientSecret))
                {
                    return BadRequest("ClientSecret is not provided in request and AzureAd:ClientSecret is not configured in appsettings.json");
                }

                using var client = new HttpClient();
                var parameters = new Dictionary<string, string>
                {
                    {"grant_type", "authorization_code"},
                    {"client_id", clientId},
                    {"code", request.AuthorizationCode},
                    {"redirect_uri", redirectUri},
                    {"scope", scope}
                };

                // Add client secret based on authentication method
                if (request.ClientAuthentication == "basic_auth")
                {
                    // Send as Basic Auth header (like Postman)
                    var credentials = Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes($"{clientId}:{clientSecret}"));
                    client.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Basic", credentials);
                }
                else
                {
                    // Send in request body (default)
                    parameters.Add("client_secret", clientSecret);
                }

                var content = new FormUrlEncodedContent(parameters);
                var tokenUrl = $"https://login.microsoftonline.com/{tenantId}/oauth2/v2.0/token";
                
                var response = await client.PostAsync(tokenUrl, content);
                var responseString = await response.Content.ReadAsStringAsync();

                if (!response.IsSuccessStatusCode)
                {
                    return BadRequest($"OAuth 2.0 authorization code request failed: {responseString}. Request URL: {tokenUrl}, Parameters: {string.Join(", ", parameters.Select(p => $"{p.Key}={p.Value}"))}");
                }

                var json = JsonDocument.Parse(responseString);
                return Ok(new
                {
                    token_name = request.TokenName ?? "GraphToken",
                    grant_type = "authorization_code",
                    access_token = json.RootElement.GetProperty("access_token").GetString(),
                    refresh_token = json.RootElement.TryGetProperty("refresh_token", out var refreshToken) ? refreshToken.GetString() : null,
                    expires_in = json.RootElement.GetProperty("expires_in").GetInt32(),
                    token_type = json.RootElement.GetProperty("token_type").GetString(),
                    scope = json.RootElement.GetProperty("scope").GetString(),
                    tenant_id = tenantId,
                    client_id = clientId,
                    redirect_uri = redirectUri,
                    client_authentication = request.ClientAuthentication ?? "body"
                });
            }
            catch (Exception ex)
            {
                return BadRequest($"OAuth 2.0 authorization code request failed: {ex.Message}");
            }
        }

        // Generate Authorization URL for OAuth 2.0 Authorization Code Flow
        [HttpPost("oauth2/authorization-url")]
        [AllowAnonymous]
        [ApiExplorerSettings(IgnoreApi = true)]
        public IActionResult GenerateAuthorizationUrl([FromBody] AuthorizationUrlRequest request)
        {
            if (request == null)
            {
                return BadRequest("Request body is required");
            }

            try
            {
                var tenantId = request.TenantId ?? _config["AzureAd:TenantId"];
                var clientId = request.ClientId ?? _config["AzureAd:ClientId"];
                var redirectUri = request.RedirectUri ?? "https://oauth.pstmn.io/v1/callback";
                var scope = request.Scope ?? "https://graph.microsoft.com/.default";
                var state = request.State ?? Guid.NewGuid().ToString();

                // Validate required configuration
                if (string.IsNullOrEmpty(tenantId))
                {
                    return BadRequest("TenantId is not provided in request and AzureAd:TenantId is not configured in appsettings.json");
                }
                if (string.IsNullOrEmpty(clientId))
                {
                    return BadRequest("ClientId is not provided in request and AzureAd:ClientId is not configured in appsettings.json");
                }

                // Build authorization URL as per OAuth 2.0 specification
                var authUrl = $"https://login.microsoftonline.com/{tenantId}/oauth2/v2.0/authorize?" +
                             $"client_id={clientId}" +
                             $"&response_type=code" +
                             $"&redirect_uri={HttpUtility.UrlEncode(redirectUri)}" +
                             $"&scope={HttpUtility.UrlEncode(scope)}" +
                             $"&state={state}" +
                             $"&response_mode=query";

                return Ok(new
                {
                    auth_url = authUrl,
                    tenant_id = tenantId,
                    client_id = clientId,
                    redirect_uri = redirectUri,
                    scope = scope,
                    state = state,
                    instructions = new
                    {
                        step1 = "Open the auth_url in your browser",
                        step2 = "Sign in with your Microsoft account",
                        step3 = "Grant consent to the requested permissions",
                        step4 = "Copy the authorization code from the redirect URL",
                        step5 = "Use the authorization code with /Token/oauth2/authorization-code endpoint"
                    }
                });
            }
            catch (Exception ex)
            {
                return BadRequest($"Failed to generate authorization URL: {ex.Message}");
            }
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

    public class TokenGenerationRequest
    {
        public string GrantType { get; set; } // "client_credentials", "password", "refresh_token"
        public string Username { get; set; } // For password grant type
        public string Password { get; set; } // For password grant type
        public string RefreshToken { get; set; } // For refresh_token grant type
        public string Scope { get; set; } // Optional, defaults will be used if not provided
    }

    public class OAuth2ClientCredentialsRequest
    {
        // These are optional - will use appsettings.json values if not provided
        [Description("Client ID from Azure AD app registration (optional - uses appsettings.json if not provided)")]
        public string? ClientId { get; set; }
        
        [Description("Client secret from Azure AD app registration (optional - uses appsettings.json if not provided)")]
        public string? ClientSecret { get; set; }
        
        [Description("Tenant ID or domain (optional - uses appsettings.json if not provided)")]
        public string? TenantId { get; set; }
        
        // User-configurable parameters with default values
        [Description("Scope for the token (defaults to https://graph.microsoft.com/.default)")]
        [DefaultValue("https://graph.microsoft.com/.default")]
        public string Scope { get; set; } = "https://graph.microsoft.com/.default";
        
        [Description("Authentication method: 'basic_auth' (Authorization header) or 'body' (request body)")]
        [DefaultValue("basic_auth")]
        public string ClientAuthentication { get; set; } = "basic_auth"; // "basic_auth" or "body"
        
        [Description("Name for the token (defaults to GraphToken)")]
        [DefaultValue("GraphToken")]
        public string TokenName { get; set; } = "GraphToken";
    }

    public class OAuth2AuthorizationCodeRequest
    {
        // These are optional - will use appsettings.json values if not provided
        [Description("Client ID from Azure AD app registration (optional - uses appsettings.json if not provided)")]
        public string? ClientId { get; set; }
        
        [Description("Client secret from Azure AD app registration (optional - uses appsettings.json if not provided)")]
        public string? ClientSecret { get; set; }
        
        [Description("Tenant ID or domain (optional - uses appsettings.json if not provided)")]
        public string? TenantId { get; set; }
        
        // Required parameter
        [Required]
        [Description("Authorization code received from the authorization URL")]
        public string AuthorizationCode { get; set; } = string.Empty;
        
        // User-configurable parameters with default values
        [Description("Redirect URI (must match the one used in authorization URL)")]
        [DefaultValue("https://oauth.pstmn.io/v1/callback")]
        public string RedirectUri { get; set; } = "https://oauth.pstmn.io/v1/callback";
        
        [Description("Scope for the token (defaults to https://graph.microsoft.com/.default)")]
        [DefaultValue("https://graph.microsoft.com/.default")]
        public string Scope { get; set; } = "https://graph.microsoft.com/.default";
        
        [Description("Name for the token (defaults to GraphToken)")]
        [DefaultValue("GraphToken")]
        public string TokenName { get; set; } = "GraphToken";
        
        [Description("Authentication method: 'basic_auth' (Authorization header) or 'body' (request body)")]
        [DefaultValue("basic_auth")]
        public string ClientAuthentication { get; set; } = "basic_auth"; // "basic_auth" or "body"
    }

    public class AuthorizationUrlRequest
    {
        // These are optional - will use appsettings.json values if not provided
        public string? ClientId { get; set; }
        public string? TenantId { get; set; }
        
        // User-configurable parameters with default values
        public string RedirectUri { get; set; } = "https://oauth.pstmn.io/v1/callback";
        public string Scope { get; set; } = "https://graph.microsoft.com/.default";
        public string? State { get; set; } // Auto-generated if not provided
    }
}