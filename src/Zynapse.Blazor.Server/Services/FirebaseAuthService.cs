using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Firebase.Auth;
using Firebase.Auth.Providers;

namespace Zynapse.Blazor.Server.Services;

public class FirebaseAuthService
{
    private readonly ILogger<FirebaseAuthService> _logger;
    private readonly FirebaseAuthClient _firebaseAuthClient;
    private readonly IHttpContextAccessor _httpContextAccessor;

    public FirebaseAuthService(
        ILogger<FirebaseAuthService> logger,
        IConfiguration configuration,
        IHttpContextAccessor httpContextAccessor)
    {
        _logger = logger;
        _httpContextAccessor = httpContextAccessor;

        var config = new FirebaseAuthConfig
        {
            ApiKey = configuration["Firebase:ApiKey"],
            AuthDomain = configuration["Firebase:AuthDomain"],
            Providers =
            [
                new EmailProvider()
            ]
        };
        _firebaseAuthClient = new FirebaseAuthClient(config);
    }

    public async Task<(bool Success, string? ErrorMessage)> SignInWithEmailAndPasswordAsync(string email,
        string password)
    {
        try
        {
            var result = await _firebaseAuthClient.SignInWithEmailAndPasswordAsync(email, password);
            var token = await result.User.GetIdTokenAsync();

            var claims = new List<Claim>
            {
                new(ClaimTypes.NameIdentifier, result.User.Uid),
                new(ClaimTypes.Email, result.User.Info.Email),
                new(ClaimTypes.Name, result.User.Info.DisplayName ?? string.Empty),
                new("FirebaseToken", token)
            };

            var claimsIdentity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
            var claimsPrincipal = new ClaimsPrincipal(claimsIdentity);

            // Set the authentication cookie
            await _httpContextAccessor.HttpContext!.SignInAsync(
                CookieAuthenticationDefaults.AuthenticationScheme,
                claimsPrincipal,
                new AuthenticationProperties
                {
                    IsPersistent = true,
                    ExpiresUtc = DateTimeOffset.UtcNow.AddDays(7)
                });

            return (true, null);
        }
        catch (FirebaseAuthException ex)
        {
            _logger.LogError(ex, "Firebase authentication error during sign in");
            return (false, GetUserFriendlyErrorMessage(ex));
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error during sign in");
            return (false, "An unexpected error occurred during sign in.");
        }
    }

    public async Task<(bool Success, string? ErrorMessage)> CreateUserWithEmailAndPasswordAsync(string email,
        string password)
    {
        try
        {
            var result = await _firebaseAuthClient.CreateUserWithEmailAndPasswordAsync(email, password);
            var token = await result.User.GetIdTokenAsync();

            var claims = new List<Claim>
            {
                new(ClaimTypes.NameIdentifier, result.User.Uid),
                new(ClaimTypes.Email, result.User.Info.Email),
                new(ClaimTypes.Name, result.User.Info.DisplayName ?? string.Empty),
                new("FirebaseToken", token)
            };

            var claimsIdentity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
            var claimsPrincipal = new ClaimsPrincipal(claimsIdentity);

            // Set the authentication cookie
            await _httpContextAccessor.HttpContext!.SignInAsync(
                CookieAuthenticationDefaults.AuthenticationScheme,
                claimsPrincipal,
                new AuthenticationProperties
                {
                    IsPersistent = true,
                    ExpiresUtc = DateTimeOffset.UtcNow.AddDays(7)
                });

            return (true, null);
        }
        catch (FirebaseAuthException ex)
        {
            _logger.LogError(ex, "Firebase authentication error during account creation");
            return (false, GetUserFriendlyErrorMessage(ex));
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error during account creation");
            return (false, "An unexpected error occurred during account creation.");
        }
    }

    private static string GetUserFriendlyErrorMessage(FirebaseAuthException ex)
    {
        return ex.Reason switch
        {
            AuthErrorReason.InvalidEmailAddress => "The email address is invalid.",
            AuthErrorReason.UserDisabled => "This account has been disabled.",
            AuthErrorReason.UserNotFound => "No account found with this email.",
            AuthErrorReason.WrongPassword => "The password is incorrect.",
            AuthErrorReason.EmailExists => "This email is already in use.",
            AuthErrorReason.WeakPassword => "The password is too weak.",
            AuthErrorReason.OperationNotAllowed => "This operation is not allowed.",
            _ => "An authentication error occurred."
        };
    }
}