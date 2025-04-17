using Zynapse.Blazor.Server.Components;
using Zynapse.Blazor.Server.Endpoints;
using Zynapse.Blazor.Server.Services;
using Microsoft.AspNetCore.Authentication.Cookies;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddRazorComponents()
    .AddInteractiveServerComponents();

builder.Services.AddCascadingAuthenticationState();
builder.Services.AddHttpContextAccessor();
builder.Services.AddAntiforgery();

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

app.MapAuthEndpoints();

app.MapRazorComponents<App>()
    .AddInteractiveServerRenderMode();

app.Run();