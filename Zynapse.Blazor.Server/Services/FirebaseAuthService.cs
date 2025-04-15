using System.Security.Claims;
using Zynapse.Blazor.Server.Models;
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

    // In constructor - remove _authStateProvider
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
            Providers = new FirebaseAuthProvider[]
            {
                new EmailProvider()
            }
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
                new Claim(ClaimTypes.NameIdentifier, result.User.Uid),
                new Claim(ClaimTypes.Email, result.User.Info.Email),
                new Claim(ClaimTypes.Name, result.User.Info.DisplayName ?? string.Empty),
                new Claim("FirebaseToken", token)
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
                new Claim(ClaimTypes.NameIdentifier, result.User.Uid),
                new Claim(ClaimTypes.Email, result.User.Info.Email),
                new Claim(ClaimTypes.Name, result.User.Info.DisplayName ?? string.Empty),
                new Claim("FirebaseToken", token)
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

    private string GetUserFriendlyErrorMessage(FirebaseAuthException ex)
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

    public async Task SetAuthCookie(User user)
    {
        try
        {
            var token = await user.GetIdTokenAsync();
            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.NameIdentifier, user.Uid),
                new Claim(ClaimTypes.Email, user.Info.Email),
                new Claim(ClaimTypes.Name, user.Info.DisplayName ?? string.Empty),
                new Claim("FirebaseToken", token)
            };

            var claimsIdentity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
            var claimsPrincipal = new ClaimsPrincipal(claimsIdentity);

            await _httpContextAccessor.HttpContext!.SignInAsync(
                CookieAuthenticationDefaults.AuthenticationScheme,
                claimsPrincipal,
                new AuthenticationProperties
                {
                    IsPersistent = true,
                    ExpiresUtc = DateTimeOffset.UtcNow.AddDays(7)
                });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error setting auth cookie");
            throw;
        }
    }

    public async Task<FirebaseUser?> GetCurrentUserAsync(ClaimsPrincipal? user)
    {
        if (user?.Identity?.IsAuthenticated != true)
        {
            return null;
        }

        try
        {
            var uid = user.FindFirst(ClaimTypes.NameIdentifier)?.Value;
            if (string.IsNullOrEmpty(uid))
            {
                return null;
            }

            var userInfo = _firebaseAuthClient.User;
            if (userInfo == null)
            {
                return null;
            }

            return new FirebaseUser
            {
                Uid = userInfo.Uid,
                Email = userInfo.Info.Email,
                DisplayName = userInfo.Info.DisplayName,
                LastSignInTimestamp = DateTime.UtcNow,
                EmailVerified = userInfo.Info.IsEmailVerified
            };
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error getting current user");
            return null;
        }
    }

    public async Task SignOut()
    {
        try
        {
            if (_firebaseAuthClient.User is not null)
            {
                _firebaseAuthClient.SignOut();
            }

            await _httpContextAccessor.HttpContext!.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error signing out");
            throw;
        }
    }

    public User? GetCurrentUser()
    {
        return _firebaseAuthClient.User;
    }
}