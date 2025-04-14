using FirebaseAdmin;
using FirebaseAdmin.Auth;
using Google.Apis.Auth.OAuth2;
using System.Security.Claims;
using Zynapse.Blazor.Server.Models;

namespace Zynapse.Blazor.Server.Services;

public class FirebaseAuthService
{
    private readonly ILogger<FirebaseAuthService> _logger;
    private readonly FirebaseAuthenticationStateProvider _authStateProvider;

    public FirebaseAuthService(
        string serviceAccountJson,
        ILogger<FirebaseAuthService> logger,
        FirebaseAuthenticationStateProvider authStateProvider)
    {
        _logger = logger;
        _authStateProvider = authStateProvider;

        if (FirebaseApp.DefaultInstance == null)
        {
            var credential = GoogleCredential.FromJson(serviceAccountJson);
            FirebaseApp.Create(new AppOptions { Credential = credential });
        }
    }

    public async Task<bool> SignInWithEmailAndPasswordAsync(string email, string password)
    {
        try
        {
            var auth = FirebaseAuth.DefaultInstance;
            var userRecord = await auth.GetUserByEmailAsync(email);
            
            // Create a custom token for the user
            var customToken = await auth.CreateCustomTokenAsync(userRecord.Uid);
            
            // Set up the authentication state
            await SetAuthCookie(userRecord.Uid);
            return true;
        }
        catch (FirebaseAuthException ex) when (ex.AuthErrorCode == AuthErrorCode.UserNotFound)
        {
            _logger.LogWarning("User not found: {Email}", email);
            throw new Exception("Invalid email or password");
        }
        catch (FirebaseAuthException ex)
        {
            _logger.LogError(ex, "Firebase authentication error for user: {Email}", email);
            throw new Exception("Authentication failed. Please try again.");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error signing in with email and password");
            throw new Exception("An unexpected error occurred. Please try again.");
        }
    }

    public async Task<bool> CreateUserWithEmailAndPasswordAsync(string email, string password)
    {
        try
        {
            var auth = FirebaseAuth.DefaultInstance;
            var userRecord = await auth.CreateUserAsync(new UserRecordArgs
            {
                Email = email,
                Password = password,
                EmailVerified = false
            });

            // Set up the authentication state
            await SetAuthCookie(userRecord.Uid);
            return true;
        }
        catch (FirebaseAuthException ex) when (ex.AuthErrorCode == AuthErrorCode.EmailAlreadyExists)
        {
            _logger.LogWarning("Email already exists: {Email}", email);
            throw new Exception("An account with this email already exists.");
        }
        catch (FirebaseAuthException ex)
        {
            _logger.LogError(ex, "Firebase authentication error creating user: {Email}", email);
            throw new Exception("Failed to create account. Please try again.");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error creating user with email and password");
            throw new Exception("An unexpected error occurred. Please try again.");
        }
    }

    private async Task SetAuthCookie(string uid)
    {
        try
        {
            var auth = FirebaseAuth.DefaultInstance;
            var user = await auth.GetUserAsync(uid);
            
            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.NameIdentifier, user.Uid),
                new Claim(ClaimTypes.Email, user.Email ?? string.Empty),
                new Claim(ClaimTypes.Name, user.DisplayName ?? string.Empty)
            };

            var identity = new ClaimsIdentity(claims, "Firebase");
            var principal = new ClaimsPrincipal(identity);

            _authStateProvider.SetUser(principal);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error setting auth cookie");
            throw;
        }
    }

    public void SignOut()
    {
        _authStateProvider.SetUser(null);
    }

    public async Task<FirebaseUser?> GetCurrentUserAsync()
    {
        var authState = await _authStateProvider.GetAuthenticationStateAsync();
        var user = authState.User;

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

            var firebaseUser = await FirebaseAuth.DefaultInstance.GetUserAsync(uid);
            return new FirebaseUser
            {
                Uid = firebaseUser.Uid,
                Email = firebaseUser.Email,
                DisplayName = firebaseUser.DisplayName,
                LastSignInTimestamp = firebaseUser.UserMetaData?.LastSignInTimestamp,
                EmailVerified = firebaseUser.EmailVerified
            };
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error getting current user");
            return null;
        }
    }
}