using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.ComponentModel.DataAnnotations;
using System.Net.Http;
using System.Text.Json;
using Swashbuckle.AspNetCore.Annotations;

namespace OIDC_ExternalID_API.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class TokenController : ControllerBase
    {
        private readonly IConfiguration _config;
        private readonly ILogger<TokenController> _logger;
        private readonly HttpClient _httpClient;

        public TokenController(IConfiguration config, ILogger<TokenController> logger, HttpClient httpClient)
        {
            _config = config;
            _logger = logger;
            _httpClient = httpClient;
        }

        /// <summary>
        /// OAuth2 Token Endpoint - Handles client credentials flow
        /// POST /token with client_id, scope, client_secret, grant_type
        /// </summary>
        /// <param name="request">OAuth2 token request</param>
        /// <returns>Access token response</returns>
        [HttpPost("Get Custom Token")]
        [AllowAnonymous]
        [ProducesResponseType(typeof(OAuth2TokenResponse), 200)]
        [ProducesResponseType(400)]
        [ProducesResponseType(401)]
        [ProducesResponseType(500)]
        [SwaggerOperation(
            Summary = "Generate Custom JWT Token",
            Description = "Generate a custom JWT token using OAuth 2.0 flows. Supports client_credentials, password, and refresh_token grant types.",
            OperationId = "GenerateCustomJwtToken",
            Tags = new[] { "Token" }
        )]
        [ApiExplorerSettings(IgnoreApi = true)]
        public async Task<IActionResult> GetToken([FromForm] OAuth2TokenRequest request)
        {
            try
            {
                if (!ModelState.IsValid)
                {
                    return BadRequest(ModelState);
                }

                // Validate required parameters
                if (string.IsNullOrEmpty(request.client_id))
                {
                    return BadRequest(new { error = "invalid_request", error_description = "client_id is required" });
                }

                if (string.IsNullOrEmpty(request.grant_type))
                {
                    return BadRequest(new { error = "invalid_request", error_description = "grant_type is required" });
                }

                // Handle different grant types
                switch (request.grant_type.ToLower())
                {
                    case "client_credentials":
                        return await HandleClientCredentialsFlow(request);

                    case "password":
                        return await HandlePasswordFlow(request);

                    case "refresh_token":
                        return await HandleRefreshTokenFlow(request);

                    default:
                        return BadRequest(new { error = "unsupported_grant_type", error_description = $"Grant type '{request.grant_type}' is not supported" });
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error processing token request for client_id: {ClientId}", request.client_id);
                return StatusCode(500, new { error = "server_error", error_description = "Internal server error" });
            }
        }

        /// <summary>
        /// Generate Azure AD token for Microsoft Graph API access using client credentials flow
        /// This token can be used for both GraphController and CustomGraphController
        /// </summary>
        /// <param name="request">Azure AD client credentials request</param>
        /// <returns>Azure AD access token response</returns>
        [HttpPost("Get AAD Token")]
        // [HttpPost("azure-ad-Token_Generation")]
        [AllowAnonymous]
        [ProducesResponseType(typeof(AzureAdTokenResponse), 200)]
        [ProducesResponseType(400)]
        [ProducesResponseType(500)]
        [SwaggerOperation(
            Summary = "Generate Azure AD Token (Client Credentials)",
            Description = "Generate an Azure AD token using client credentials flow. This token works with both GraphController and CustomGraphController endpoints.",
            OperationId = "GenerateAzureAdToken",
            Tags = new[] { "Token" }
        )]
        public async Task<IActionResult> GetAzureAdToken([FromBody] AzureAdClientCredentialsRequest request)
        {
            try
            {
                if (!ModelState.IsValid)
                {
                    return BadRequest(ModelState);
                }

                // Validate required parameters
                if (string.IsNullOrEmpty(request.client_id))
                {
                    return BadRequest(new { error = "invalid_request", error_description = "client_id is required" });
                }

                if (string.IsNullOrEmpty(request.client_secret))
                {
                    return BadRequest(new { error = "invalid_request", error_description = "client_secret is required" });
                }

                // Get Azure AD tenant configuration
                var tenantId = _config["AzureAd:TenantId"];
                if (string.IsNullOrEmpty(tenantId))
                {
                    return StatusCode(500, new { error = "configuration_error", error_description = "Azure AD tenant configuration is missing" });
                }

                // Use the scope provided by user or default to Microsoft Graph
                var scope = request.scope ?? "https://graph.microsoft.com/.default";

                // Create token request using client credentials flow
                var tokenRequest = new FormUrlEncodedContent(new[]
                {
                    new KeyValuePair<string, string>("grant_type", "client_credentials"),
                    new KeyValuePair<string, string>("client_id", request.client_id),
                    new KeyValuePair<string, string>("client_secret", request.client_secret),
                    new KeyValuePair<string, string>("scope", scope)
                });

                // Request token from Azure AD
                var tokenResponse = await _httpClient.PostAsync($"https://login.microsoftonline.com/{tenantId}/oauth2/v2.0/token", tokenRequest);
                
                if (tokenResponse.IsSuccessStatusCode)
                {
                    var responseContent = await tokenResponse.Content.ReadAsStringAsync();
                    var tokenData = JsonSerializer.Deserialize<AzureAdTokenResponse>(responseContent);
                    
                    return Ok(tokenData);
                }
                else
                {
                    var errorContent = await tokenResponse.Content.ReadAsStringAsync();
                    _logger.LogError($"Azure AD token request failed: {tokenResponse.StatusCode} - {errorContent}");
                    
                    // Try to parse error response
                    try
                    {
                        var errorData = JsonSerializer.Deserialize<AzureAdErrorResponse>(errorContent);
                        return BadRequest(errorData);
                    }
                    catch
                    {
                        return BadRequest(new { error = "azure_ad_error", error_description = $"Azure AD token request failed: {errorContent}" });
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error generating Azure AD token for client_id: {ClientId}", request?.client_id);
                return StatusCode(500, new { error = "server_error", error_description = "Internal server error" });
            }
        }

        /// <summary>
        /// Generate Azure AD token using client credentials flow (for service-to-service scenarios)
        /// This token can be used for both GraphController and CustomGraphController
        /// </summary>
        /// <param name="request">Azure AD client credentials request</param>
        /// <returns>Azure AD access token response</returns>
        [HttpPost("azure-ad/client-credentials")]
        [AllowAnonymous]
        [ProducesResponseType(typeof(AzureAdTokenResponse), 200)]
        [ProducesResponseType(400)]
        [ProducesResponseType(500)]
        [SwaggerOperation(
            Summary = "Generate Azure AD Token (Alternative Client Credentials)",
            Description = "Alternative endpoint for generating Azure AD tokens using client credentials flow. Same functionality as /Token/azure-ad.",
            OperationId = "GenerateAzureAdClientCredentialsToken",
            Tags = new[] { "Token" }
        )]
        [ApiExplorerSettings(IgnoreApi = true)]
        public async Task<IActionResult> GetAzureAdClientCredentialsToken([FromBody] AzureAdClientCredentialsRequest request)
        {
            try
            {
                if (!ModelState.IsValid)
                {
                    return BadRequest(ModelState);
                }

                // Validate required parameters
                if (string.IsNullOrEmpty(request.client_id))
                {
                    return BadRequest(new { error = "invalid_request", error_description = "client_id is required" });
                }

                if (string.IsNullOrEmpty(request.client_secret))
                {
                    return BadRequest(new { error = "invalid_request", error_description = "client_secret is required" });
                }

                // Get Azure AD tenant configuration
                var tenantId = _config["AzureAd:TenantId"];
                if (string.IsNullOrEmpty(tenantId))
                {
                    return StatusCode(500, new { error = "configuration_error", error_description = "Azure AD tenant configuration is missing" });
                }

                // Use the scope provided by user or default to Microsoft Graph
                var scope = request.scope ?? "https://graph.microsoft.com/.default";

                // Create token request using client credentials flow
                var tokenRequest = new FormUrlEncodedContent(new[]
                {
                    new KeyValuePair<string, string>("grant_type", "client_credentials"),
                    new KeyValuePair<string, string>("client_id", request.client_id),
                    new KeyValuePair<string, string>("client_secret", request.client_secret),
                    new KeyValuePair<string, string>("scope", scope)
                });

                // Request token from Azure AD
                var tokenResponse = await _httpClient.PostAsync($"https://login.microsoftonline.com/{tenantId}/oauth2/v2.0/token", tokenRequest);
                
                if (tokenResponse.IsSuccessStatusCode)
                {
                    var responseContent = await tokenResponse.Content.ReadAsStringAsync();
                    var tokenData = JsonSerializer.Deserialize<AzureAdTokenResponse>(responseContent);
                    
                    return Ok(tokenData);
                }
                else
                {
                    var errorContent = await tokenResponse.Content.ReadAsStringAsync();
                    _logger.LogError($"Azure AD client credentials token request failed: {tokenResponse.StatusCode} - {errorContent}");
                    
                    // Try to parse error response
                    try
                    {
                        var errorData = JsonSerializer.Deserialize<AzureAdErrorResponse>(errorContent);
                        return BadRequest(errorData);
                    }
                    catch
                    {
                        return BadRequest(new { error = "azure_ad_error", error_description = $"Azure AD token request failed: {errorContent}" });
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error generating Azure AD client credentials token for client_id: {ClientId}", request?.client_id);
                return StatusCode(500, new { error = "server_error", error_description = "Internal server error" });
            }
        }

        private async Task<IActionResult> HandleClientCredentialsFlow(OAuth2TokenRequest request)
        {
            // Validate client credentials
            if (string.IsNullOrEmpty(request.client_secret))
            {
                return BadRequest(new { error = "invalid_request", error_description = "client_secret is required for client_credentials grant" });
            }

            // In a real implementation, validate client_id and client_secret against your client store
            if (!ValidateClientCredentials(request.client_id, request.client_secret))
            {
                return Unauthorized(new { error = "invalid_client", error_description = "Invalid client credentials" });
            }

            // Generate access token
            var token = GenerateAccessToken(request.client_id, request.scope);
            var expiresIn = 3600; // 1 hour

            return Ok(new OAuth2TokenResponse
            {
                access_token = token,
                token_type = "Bearer",
                expires_in = expiresIn,
                scope = request.scope ?? "api://default"
            });
        }

        private async Task<IActionResult> HandlePasswordFlow(OAuth2TokenRequest request)
        {
            // Validate required parameters for password grant
            if (string.IsNullOrEmpty(request.username))
            {
                return BadRequest(new { error = "invalid_request", error_description = "username is required for password grant" });
            }

            if (string.IsNullOrEmpty(request.password))
            {
                return BadRequest(new { error = "invalid_request", error_description = "password is required for password grant" });
            }

            // In a real implementation, validate username and password against your user store
            if (!ValidateUserCredentials(request.username, request.password))
            {
                return Unauthorized(new { error = "invalid_grant", error_description = "Invalid username or password" });
            }

            // Generate access token
            var token = GenerateAccessToken(request.username, request.scope);
            var expiresIn = 3600; // 1 hour

            return Ok(new OAuth2TokenResponse
            {
                access_token = token,
                token_type = "Bearer",
                expires_in = expiresIn,
                scope = request.scope ?? "api://default"
            });
        }

        private async Task<IActionResult> HandleRefreshTokenFlow(OAuth2TokenRequest request)
        {
            // Validate required parameters for refresh token grant
            if (string.IsNullOrEmpty(request.refresh_token))
            {
                return BadRequest(new { error = "invalid_request", error_description = "refresh_token is required for refresh_token grant" });
            }

            // In a real implementation, validate refresh token against your token store
            if (!ValidateRefreshToken(request.refresh_token))
            {
                return Unauthorized(new { error = "invalid_grant", error_description = "Invalid refresh token" });
            }

            // Generate new access token
            var token = GenerateAccessToken("user", request.scope);
            var expiresIn = 3600; // 1 hour

            return Ok(new OAuth2TokenResponse
            {
                access_token = token,
                token_type = "Bearer",
                expires_in = expiresIn,
                scope = request.scope ?? "api://default"
            });
        }

        private string GenerateAccessToken(string subject, string scope)
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes(GetJwtSecret());

            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.NameIdentifier, subject),
                new Claim("sub", subject),
                new Claim("jti", Guid.NewGuid().ToString()),
                new Claim("iat", DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString(), ClaimValueTypes.Integer64)
            };

            // Add scope claim if provided
            if (!string.IsNullOrEmpty(scope))
            {
                claims.Add(new Claim("scope", scope));
            }

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(claims),
                Expires = DateTime.UtcNow.AddHours(1),
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
            };

            var token = tokenHandler.CreateToken(tokenDescriptor);
            return tokenHandler.WriteToken(token);
        }

        private bool ValidateClientCredentials(string clientId, string clientSecret)
        {
            // In a real implementation, validate against your client store
            // For demo purposes, accept any non-empty client credentials
            return !string.IsNullOrEmpty(clientId) && !string.IsNullOrEmpty(clientSecret);
        }

        private bool ValidateUserCredentials(string username, string password)
        {
            // In a real implementation, validate against your user store
            // For demo purposes, accept any non-empty username/password
            return !string.IsNullOrEmpty(username) && !string.IsNullOrEmpty(password);
        }

        private bool ValidateRefreshToken(string refreshToken)
        {
            // In a real implementation, validate refresh token against your token store
            // For demo purposes, accept any non-empty refresh token
            return !string.IsNullOrEmpty(refreshToken);
        }

        private string GetJwtSecret()
        {
            var secret = _config["Jwt:Secret"];
            if (string.IsNullOrEmpty(secret))
            {
                // Generate a random secret if not configured
                using var rng = new RNGCryptoServiceProvider();
                var bytes = new byte[32];
                rng.GetBytes(bytes);
                secret = Convert.ToBase64String(bytes);
                _logger.LogWarning("JWT secret not configured. Using generated secret. Please configure Jwt:Secret in appsettings.json");
            }
            return secret;
        }

        /// <summary>
        /// Validate an access token
        /// </summary>
        /// <param name="request">Token validation request</param>
        /// <returns>Token validation result</returns>
        [HttpPost("validate")]
        [AllowAnonymous]
        [ApiExplorerSettings(IgnoreApi = true)]
        public IActionResult ValidateToken([FromBody] TokenValidationRequest request)
        {
            try
            {
                if (string.IsNullOrEmpty(request.access_token))
                {
                    return BadRequest(new { error = "invalid_request", error_description = "access_token is required" });
                }

                var tokenHandler = new JwtSecurityTokenHandler();
                var key = Encoding.ASCII.GetBytes(GetJwtSecret());

                var validationParameters = new TokenValidationParameters
                {
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKey = new SymmetricSecurityKey(key),
                    ValidateIssuer = false,
                    ValidateAudience = false,
                    ClockSkew = TimeSpan.Zero
                };

                try
                {
                    var principal = tokenHandler.ValidateToken(request.access_token, validationParameters, out var validatedToken);

                    var subject = principal.FindFirst(ClaimTypes.NameIdentifier)?.Value;
                    var scope = principal.FindFirst("scope")?.Value;

                    return Ok(new TokenValidationResponse
                    {
                        valid = true,
                        sub = subject,
                        scope = scope,
                        exp = validatedToken.ValidTo,
                        iat = validatedToken.ValidFrom
                    });
                }
                catch (SecurityTokenExpiredException)
                {
                    return Ok(new TokenValidationResponse
                    {
                        valid = false,
                        error = "token_expired"
                    });
                }
                catch (Exception)
                {
                    return Ok(new TokenValidationResponse
                    {
                        valid = false,
                        error = "invalid_token"
                    });
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error validating token");
                return StatusCode(500, new { error = "server_error", error_description = "Internal server error" });
            }
        }
    }

    public class OAuth2TokenRequest
    {
        public string client_id { get; set; }
        public string client_secret { get; set; }
        public string scope { get; set; }
        public string grant_type { get; set; }
        public string username { get; set; }
        public string password { get; set; }
        public string refresh_token { get; set; }
    }

    public class OAuth2TokenResponse
    {
        public string access_token { get; set; }
        public string token_type { get; set; }
        public int expires_in { get; set; }
        public string scope { get; set; }
        public string refresh_token { get; set; }
    }

    public class TokenValidationRequest
    {
        public string access_token { get; set; }
    }

    public class TokenValidationResponse
    {
        public bool valid { get; set; }
        public string sub { get; set; }
        public string scope { get; set; }
        public DateTime? exp { get; set; }
        public DateTime? iat { get; set; }
        public string error { get; set; }
    }

    public class AzureAdTokenRequest
    {
        public string username { get; set; }
        public string password { get; set; }
        public string[] scopes { get; set; }
    }

    public class AzureAdClientCredentialsRequest
    {
        public string client_id { get; set; }
        public string client_secret { get; set; }
        public string scope { get; set; }
    }

    public class AzureAdTokenResponse
    {
        public string access_token { get; set; }
        public string token_type { get; set; }
        public int expires_in { get; set; }
        public string scope { get; set; }
        public string refresh_token { get; set; }
        public string id_token { get; set; }
    }

    public class AzureAdErrorResponse
    {
        public string error { get; set; }
        public string error_description { get; set; }
        public string error_codes { get; set; }
        public string timestamp { get; set; }
        public string trace_id { get; set; }
        public string correlation_id { get; set; }
    }
}