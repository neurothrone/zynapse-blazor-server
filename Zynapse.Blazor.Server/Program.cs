using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Authentication;
using Zynapse.Blazor.Server.Components;
using Zynapse.Blazor.Server.Services;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Mvc;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container
builder.Services.AddRazorComponents()
    .AddInteractiveServerComponents();

// Use default AuthenticationStateProvider (no custom one)
builder.Services.AddCascadingAuthenticationState();
builder.Services.AddHttpContextAccessor();

// Add authentication services
builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(options =>
    {
        options.Cookie.Name = "Zynapse.Auth";
        options.Cookie.HttpOnly = true;
        options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
        options.Cookie.SameSite = SameSiteMode.Strict;
        options.ExpireTimeSpan = TimeSpan.FromDays(7);
        options.LoginPath = "/login";
        options.LogoutPath = "/";
        options.AccessDeniedPath = "/access-denied";
    });

// Add authorization services
builder.Services.AddAuthorization();

// Configure Firebase
var firebaseConfig = builder.Configuration.GetSection("Firebase");
var apiKey = firebaseConfig["ApiKey"];
var authDomain = firebaseConfig["AuthDomain"];

if (string.IsNullOrEmpty(apiKey))
    throw new Exception("Firebase API key is not configured");
if (string.IsNullOrEmpty(authDomain))
    throw new Exception("Firebase Auth Domain is not configured");

builder.Services.AddScoped(provider => new FirebaseAuthService(
    provider.GetRequiredService<ILogger<FirebaseAuthService>>(),
    provider.GetRequiredService<IConfiguration>(),
    provider.GetRequiredService<IHttpContextAccessor>()));

var app = builder.Build();

// Configure the HTTP request pipeline
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error");
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();
app.UseAuthentication(); // <- This must come before UseAuthorization
app.UseAuthorization();

app.UseAntiforgery();

app.MapPost("/login-user", async (
    HttpContext context,
    IAntiforgery antiforgery,
    FirebaseAuthService authService) =>
{
    try
    {
        await antiforgery.ValidateRequestAsync(context);
    }
    catch (AntiforgeryValidationException)
    {
        return Results.BadRequest("Invalid or missing antiforgery token.");
    }

    var form = await context.Request.ReadFormAsync();
    var email = form["Email"];
    var password = form["Password"];

    var (success, errorMessage) =
        await authService.SignInWithEmailAndPasswordAsync(email!, password!);

    if (!success)
    {
        return Results.BadRequest(errorMessage ?? "Invalid credentials.");
    }

    return Results.Redirect("/profile");
});

app.MapPost("/logout-user", async (HttpContext context) =>
{
    await context.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
    return Results.Redirect("/");
});

app.MapRazorComponents<App>()
    .AddInteractiveServerRenderMode();

app.Run();

public record LoginRequest(string Email, string Password);