using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;
using System.Net.Http;
using System.Threading.Tasks;
using System.Collections.Generic;
using System.Text.Json;
using Microsoft.Graph;
using Microsoft.Extensions.Configuration;

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
} 