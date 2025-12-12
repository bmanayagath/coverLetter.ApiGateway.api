using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;

var builder = WebApplication.CreateBuilder(args);

// Load optional secrets file (not committed). Useful for local dev.
// For production prefer __User Secrets__ or environment variables.
builder.Configuration.AddJsonFile("appsettings.Secrets.json", optional: true, reloadOnChange: true);

// Simple JWT configuration with fallbacks.
// For production, move these into user secrets or environment variables.
builder.Configuration["Jwt:Issuer"] ??= "example-issuer";
builder.Configuration["Jwt:Audience"] ??= "example-audience";
builder.Configuration["Jwt:Key"] ??= "super_secret_key_123!";

builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

// Add authentication / authorization for optional middleware-based validation
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateIssuerSigningKey = true,
            ValidIssuer = builder.Configuration["Jwt:Issuer"],
            ValidAudience = builder.Configuration["Jwt:Audience"],
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(builder.Configuration["Jwt:Key"])),
            ValidateLifetime = true,
            ClockSkew = TimeSpan.FromSeconds(30)
        };
    });

builder.Services.AddAuthorization();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

// Enable authentication/authorization middleware (optional for endpoints that call ValidateToken manually)
app.UseAuthentication();
app.UseAuthorization();


// Minimal API endpoint to validate a JWT token.
// - Accepts token in Authorization header: "Authorization: Bearer {token}"
// - Or accepts JSON body: { "token": "eyJ..." }
app.MapPost("/validate-token", async (HttpRequest request) =>
{
    string? token = null;

    // Try Authorization header first
    if (request.Headers.TryGetValue("Authorization", out var authHeaders))
    {
        var header = authHeaders.FirstOrDefault();
        if (!string.IsNullOrWhiteSpace(header) && header.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
        {
            token = header.Substring("Bearer ".Length).Trim();
        }
    }

    // If no header token, try reading JSON body { "token": "..." }
    if (string.IsNullOrWhiteSpace(token))
    {
        try
        {
            var body = await request.ReadFromJsonAsync<TokenRequest>();
            token = body?.Token;
        }
        catch
        {
            // ignore parse errors - will be handled below
        }
    }

    if (string.IsNullOrWhiteSpace(token))
    {
        return Results.BadRequest(new { valid = false, error = "No token provided" });
    }

    var tokenHandler = new JwtSecurityTokenHandler();
    var validationParameters = new TokenValidationParameters
    {
        ValidateIssuer = true,
        ValidateAudience = true,
        ValidateIssuerSigningKey = true,
        ValidIssuer = builder.Configuration["Jwt:Issuer"],
        ValidAudience = builder.Configuration["Jwt:Audience"],
        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(builder.Configuration["Jwt:Key"])),
        ValidateLifetime = true,
        ClockSkew = TimeSpan.FromSeconds(30)
    };

    try
    {
        var principal = tokenHandler.ValidateToken(token, validationParameters, out var validatedToken);

        // Optionally ensure token is a JWT (not required but good practice)
        if (validatedToken is not JwtSecurityToken jwt)
        {
            return Results.Unauthorized();
        }

        // Convert claims to a simple dictionary for output
        var claims = principal.Claims.GroupBy(c => c.Type)
            .ToDictionary(g => g.Key, g => g.Select(c => c.Value).ToArray());

        return Results.Ok(new
        {
            valid = true,
            issuer = jwt.Issuer,
            audience = jwt.Audiences,
            claims
        });
    }
    catch (SecurityTokenException)
    {
        return Results.Unauthorized();
    }
    catch (Exception ex)
    {
        // For diagnostics in development you might return error details; avoid leaking info in production.
        return Results.BadRequest(new { valid = false, error = ex.Message });
    }
})
.WithName("ValidateToken");

app.Run();

internal record TokenRequest(string Token);
