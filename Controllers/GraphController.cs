using Microsoft.AspNetCore.Mvc;
using Microsoft.Graph;
using Microsoft.Graph.Models;
using Microsoft.Graph.Models.ODataErrors;
using OIDC_ExternalID_API.Models;

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



        [HttpGet("user")]
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




        [HttpGet("user/by-email")]
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




        [HttpPatch("user")]
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




        [HttpPatch("UpdateUserLimitedAttributes")]
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



    }
} 
