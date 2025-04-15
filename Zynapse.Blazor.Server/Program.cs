using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Authentication;
using Zynapse.Blazor.Server.Components;
using Zynapse.Blazor.Server.Services;
using Microsoft.AspNetCore.Authentication.Cookies;
using System.Web;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddRazorComponents()
    .AddInteractiveServerComponents();

builder.Services.AddCascadingAuthenticationState();
builder.Services.AddHttpContextAccessor();

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

if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error");
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();
app.UseAuthentication();
app.UseAuthorization();

app.UseAntiforgery();

app.MapPost("/register-user", async (
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
        return Results.Redirect("/register?error=Invalid+or+missing+antiforgery+token");
    }

    var form = await context.Request.ReadFormAsync();
    var email = form["Email"];
    var password = form["Password"];
    var confirmPassword = form["ConfirmPassword"];

    if (string.IsNullOrEmpty(email) || string.IsNullOrEmpty(password) || string.IsNullOrEmpty(confirmPassword))
    {
        return Results.Redirect("/register?error=Email,+password,+and+confirm+password+are+required");
    }

    if (password != confirmPassword)
    {
        return Results.Redirect("/register?error=Passwords+do+not+match");
    }

    var (success, errorMessage) = 
        await authService.CreateUserWithEmailAndPasswordAsync(email!, password!);

    if (!success)
    {
        var encodedError = HttpUtility.UrlEncode(errorMessage ?? "Account registration failed");
        return Results.Redirect($"/register?error={encodedError}");
    }
    
    return Results.Redirect("/profile");
});

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
        return Results.Redirect("/login?error=Invalid+or+missing+antiforgery+token");
    }

    var form = await context.Request.ReadFormAsync();
    var email = form["Email"];
    var password = form["Password"];

    if (string.IsNullOrEmpty(email) || string.IsNullOrEmpty(password))
    {
        return Results.Redirect("/login?error=Email+and+password+are+required");
    }

    var (success, errorMessage) =
        await authService.SignInWithEmailAndPasswordAsync(email!, password!);

    if (!success)
    {
        var encodedError = HttpUtility.UrlEncode(errorMessage ?? "Invalid credentials");
        return Results.Redirect($"/login?error={encodedError}");
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