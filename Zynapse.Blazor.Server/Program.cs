using Zynapse.Blazor.Server.Components;
using Zynapse.Blazor.Server.Services;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.AspNetCore.Authentication.Cookies;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddRazorComponents()
    .AddInteractiveServerComponents();

builder.Services.AddCascadingAuthenticationState();
builder.Services.AddScoped<FirebaseAuthenticationStateProvider>();
builder.Services.AddScoped<AuthenticationStateProvider>(sp =>
    sp.GetRequiredService<FirebaseAuthenticationStateProvider>()
);

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

// Configure Firebase
var firebaseConfigPath = Path.Combine(builder.Environment.ContentRootPath, "firebase-service-account.json");
if (!File.Exists(firebaseConfigPath))
{
    throw new InvalidOperationException(
        "Firebase service account file not found. Please follow these steps:\n" +
        "1. Go to Firebase Console → Project Settings → Service Accounts\n" +
        "2. Click 'Generate New Private Key'\n" +
        "3. Save the downloaded JSON file as 'firebase-service-account.json' in the project root"
    );
}

var firebaseConfigJson = await File.ReadAllTextAsync(firebaseConfigPath);

// Register Firebase services
builder.Services.AddScoped<FirebaseAuthService>(sp =>
    new FirebaseAuthService(
        firebaseConfigJson,
        sp.GetRequiredService<ILogger<FirebaseAuthService>>(),
        sp.GetRequiredService<FirebaseAuthenticationStateProvider>()
    )
);

// Add authorization
builder.Services.AddAuthorization();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error", createScopeForErrors: true);
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}

app.UseHttpsRedirection();

app.UseStaticFiles();
app.UseAntiforgery();

// Add authentication and authorization middleware
app.UseAuthentication();
app.UseAuthorization();

app.MapRazorComponents<App>()
    .AddInteractiveServerRenderMode();

app.Run();