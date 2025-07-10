using Azure.Identity;
using Microsoft.AspNetCore.Builder;
using Microsoft.Graph;
using Microsoft.OpenApi.Models;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using System.Text;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.

builder.Services.AddControllers();

// Add JWT Bearer Authentication
var jwtSecret = builder.Configuration["Jwt:Secret"];
if (string.IsNullOrEmpty(jwtSecret))
{
    // Generate a random secret if not configured
    using var rng = new System.Security.Cryptography.RNGCryptoServiceProvider();
    var bytes = new byte[32];
    rng.GetBytes(bytes);
    jwtSecret = Convert.ToBase64String(bytes);
}

builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.ASCII.GetBytes(jwtSecret)),
            ValidateIssuer = false,
            ValidateAudience = false,
            ClockSkew = TimeSpan.Zero
        };
    });

builder.Services.AddAuthorization();

// Add session support for OAuth 2.0 authorization code flow
builder.Services.AddDistributedMemoryCache();
builder.Services.AddSession(options =>
{
    options.IdleTimeout = TimeSpan.FromMinutes(30);
    options.Cookie.HttpOnly = true;
    options.Cookie.IsEssential = true;
});

// Add the Graph API client
var scopes = new[] { "https://graph.microsoft.com/.default" };
var tenantId = builder.Configuration["AzureAd:TenantId"];
var clientId = builder.Configuration["AzureAd:ClientId"];
var clientSecret = builder.Configuration["AzureAd:ClientSecret"];

var clientSecretCredential = new ClientSecretCredential(tenantId, clientId, clientSecret);

builder.Services.AddSingleton(new GraphServiceClient(clientSecretCredential, scopes));

// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(c =>
{
    c.SwaggerDoc("v1", new OpenApiInfo { Title = "External ID Graph Api", Version = "v1" });

    // Add Bearer token authentication for Swagger UI
    c.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
    {
        Description = "JWT Authorization header using the Bearer scheme. Example: \"Authorization: Bearer {token}\"",
        Name = "Authorization",
        In = ParameterLocation.Header,
        Type = SecuritySchemeType.ApiKey,
        Scheme = "Bearer"
    });

    c.AddSecurityRequirement(new OpenApiSecurityRequirement
    {
        {
            new OpenApiSecurityScheme
            {
                Reference = new OpenApiReference
                {
                    Type = ReferenceType.SecurityScheme,
                    Id = "Bearer"
                }
            },
            new string[] {}
        }
    });

    // // OAuth2 Authorization Code flow for Azure AD with PKCE (any Microsoft user)
    // c.AddSecurityDefinition("oauth2", new OpenApiSecurityScheme
    // {
    //     Type = SecuritySchemeType.OAuth2,
    //     Flows = new OpenApiOAuthFlows
    //     {
    //         AuthorizationCode = new OpenApiOAuthFlow
    //         {
    //             AuthorizationUrl = new Uri("https://login.microsoftonline.com/volvogroupextid.onmicrosoft.com/oauth2/v2.0/authorize"),
    //             TokenUrl = new Uri("https://login.microsoftonline.com/volvogroupextid.onmicrosoft.com/oauth2/v2.0/token"),
    //             //AuthorizationUrl = new Uri("https://login.microsoftonline.com/common/oauth2/v2.0/authorize"),
    //             //TokenUrl = new Uri("https://login.microsoftonline.com/common/oauth2/v2.0/token"),
    //             Scopes = new Dictionary<string, string>
    //             {
    //                 { "User.Read.All", "Read all users' full profiles" },
    //                 { "User.ReadWrite.All", "Read and write all users' full profiles" },
    //                 { "Directory.AccessAsUser.All", "Access directory as the signed-in user" },
    //                 { "offline_access", "Maintain access to data you have given it access to" },
    //                 { "openid", "Sign users in" }
    //             }
    //         }
    //     }
    // });
    // c.AddSecurityRequirement(new OpenApiSecurityRequirement
    // {
    //     {
    //         new OpenApiSecurityScheme
    //         {
    //             Reference = new OpenApiReference
    //             {
    //                 Type = ReferenceType.SecurityScheme,
    //                 Id = "oauth2"
    //             }
    //         },
    //         new[] { "User.Read.All", "User.ReadWrite.All", "Directory.AccessAsUser.All", "offline_access", "openid" }
    //     }
    // });

    // Read the README.md file
    //var readmeText = File.ReadAllText("README.md");
    //c.SwaggerDoc("v1", new OpenApiInfo
    //{
    //    Title = "External ID Graph Api",
    //    Version = "v1",
    //    Description = readmeText // This will show your README in Swagger UI
    //});

});

// Add this before builder.Build()
builder.Services.AddCors(options =>
{
    options.AddPolicy("AllowSwaggerUI", policy =>
    {
        policy
            //https://localhost:7110
            .WithOrigins("https://localhost:7110", 
            "https://externalid-restapi-hcbvbpeef6c8gbay.southeastasia-01.azurewebsites.net"
            ) // <-- Replace with your Swagger UI origin
            //.AllowAnyOrigin()
            .AllowAnyHeader()
            .AllowAnyMethod();
    });
});

builder.Services.AddHttpClient();
builder.Services.AddHttpContextAccessor();

var app = builder.Build();

// Configure the HTTP request pipeline.
// if (app.Environment.IsDevelopment())
// {
    app.UseSwagger();
    app.UseSwaggerUI(c =>
    {
        c.SwaggerEndpoint("/swagger/v1/swagger.json", "My API V1");
        // c.OAuthClientId("your-client-id"); // TODO: Replace with your Azure AD App Registration client ID
        // c.OAuthScopes("User.Read.All", "User.ReadWrite.All", "Directory.AccessAsUser.All", "offline_access", "openid");
        // c.OAuthUsePkce(); // Required for Authorization Code flow with PKCE
        // c.OAuth2RedirectUrl("https://externalid-restapi-hcbvbpeef6c8gbay.southeastasia-01.azurewebsites.net/swagger/oauth2-redirect.html"); // TODO: Ensure this matches your Azure AD app registration
        // https://localhost:7110/swagger/oauth2-redirect.html
    });
// }

// After app creation, before app.UseAuthorization()
app.UseCors("AllowSwaggerUI");

app.UseHttpsRedirection();

// Add session middleware
app.UseSession();

app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

app.Run();
