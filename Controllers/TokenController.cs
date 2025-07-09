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

        // [HttpPost("store-code-verifier")]
        // [AllowAnonymous]
        // public IActionResult StoreCodeVerifier([FromBody] string codeVerifier)
        // {
        //     if (string.IsNullOrEmpty(codeVerifier))
        //     {
        //         return BadRequest("code_verifier is required");
        //     }
        //     HttpContext.Session.SetString("pkce_code_verifier", codeVerifier);
        //     return Ok();
        // }

        private async Task<object> ExchangeCodeForToken(string authorizationCode)
        {
            var tenantId = _config["AzureAd:TenantId"];
            var clientId = _config["AzureAd:ClientId"];
            var redirectUri = $"{Request.Scheme}://{Request.Host}/Token/callback";
            // var codeVerifier = HttpContext.Session.GetString("pkce_code_verifier");
            // if (string.IsNullOrEmpty(codeVerifier))
            // {
            //     throw new Exception("PKCE code_verifier is missing from session. Please initiate the flow correctly.");
            // }

            using var client = new HttpClient();
            var parameters = new Dictionary<string, string>
            {
                {"client_id", clientId},
                {"scope", "Directory.AccessAsUser.All User.Read"},
                {"code", authorizationCode},
                {"redirect_uri", redirectUri},
                {"grant_type", "authorization_code"}
                // ,{"code_verifier", codeVerifier}
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
    }

    public class RefreshTokenRequest
    {
        public string RefreshToken { get; set; }
    }
}