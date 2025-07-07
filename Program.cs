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

    // OAuth2 Authorization Code flow for Azure AD with PKCE (any Microsoft user)
    c.AddSecurityDefinition("oauth2", new OpenApiSecurityScheme
    {
        Type = SecuritySchemeType.OAuth2,
        Flows = new OpenApiOAuthFlows
        {
            AuthorizationCode = new OpenApiOAuthFlow
            {
                //AuthorizationUrl = new Uri("https://login.microsoftonline.com/volvogroupextid.onmicrosoft.com/oauth2/v2.0/authorize"),
                //TokenUrl = new Uri("https://login.microsoftonline.com/volvogroupextid.onmicrosoft.com/oauth2/v2.0/token"),

                AuthorizationUrl = new Uri("https://login.microsoftonline.com/common/oauth2/v2.0/authorize"),
                TokenUrl = new Uri("https://login.microsoftonline.com/common/oauth2/v2.0/token"),
                Scopes = new Dictionary<string, string>
                {
                    { "api.read", "Read access to API, as mentioned in microsoft document" }
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
        c.OAuthClientId("your-client-id"); // TODO: Replace with your Azure AD App Registration client ID
        c.OAuthScopes("api.read");
        c.OAuthUsePkce(); // Required for Authorization Code flow with PKCE
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
