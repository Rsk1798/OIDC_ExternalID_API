using Azure.Identity;
using Microsoft.AspNetCore.Builder;
using Microsoft.Graph;
using Microsoft.OpenApi.Models;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.

builder.Services.AddControllers();

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

    // OAuth2 Authorization Code flow for Azure AD
    c.AddSecurityDefinition("oauth2", new OpenApiSecurityScheme
    {
        Type = SecuritySchemeType.OAuth2,
        Flows = new OpenApiOAuthFlows
        {
            AuthorizationCode = new OpenApiOAuthFlow
            {
                // volvogroupextid.onmicrosoft.com
                AuthorizationUrl = new Uri("https://login.microsoftonline.com/volvogroupextid.onmicrosoft.com/oauth2/v2.0/authorize"), // TODO: Replace {tenant-id}
                TokenUrl = new Uri("https://login.microsoftonline.com/volvogroupextid.onmicrosoft.com/oauth2/v2.0/token"), // TODO: Replace {tenant-id}
                Scopes = new Dictionary<string, string>
                {
                    { "api.read", "Read access to API" }
                }
            }
        }
    });
    c.AddSecurityRequirement(new OpenApiSecurityRequirement
    {
        {
            new OpenApiSecurityScheme
            {
                Reference = new OpenApiReference
                {
                    Type = ReferenceType.SecurityScheme,
                    Id = "oauth2"
                }
            },
            new[] { "api.read" }
        }
    });

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
            .WithOrigins("https://localhost:7110") // <-- Replace with your Swagger UI origin
            .AllowAnyHeader()
            .AllowAnyMethod();
    });
});

var app = builder.Build();

// Configure the HTTP request pipeline.
// if (app.Environment.IsDevelopment())
// {
    app.UseSwagger();
    app.UseSwaggerUI(c =>
    {
        c.SwaggerEndpoint("/swagger/v1/swagger.json", "My API V1");
        c.OAuthClientId("your-client-id"); // TODO: Replace with your Azure AD App Registration client ID
        c.OAuthScopes("api.read"); // TODO: Replace with your scope(s)
        c.OAuthUsePkce(); // Required for Authorization Code flow
        // c.OAuthRedirectUrl("https://localhost:7110/swagger/oauth2-redirect.html"); // TODO: Ensure this matches your Azure AD app registration
        c.OAuth2RedirectUrl("https://localhost:7110/swagger/oauth2-redirect.html"); // TODO: Ensure this matches your Azure AD app registration
    });
// }

// After app creation, before app.UseAuthorization()
app.UseCors("AllowSwaggerUI");

app.UseHttpsRedirection();

// Add session middleware
app.UseSession();

app.UseAuthorization();

app.MapControllers();

app.Run();
