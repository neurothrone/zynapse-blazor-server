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
    private readonly FirebaseAuthenticationStateProvider _authStateProvider;
    private readonly FirebaseAuthClient _firebaseAuthClient;

    public FirebaseAuthService(
        ILogger<FirebaseAuthService> logger,
        FirebaseAuthenticationStateProvider authStateProvider,
        IConfiguration configuration)
    {
        _logger = logger;
        _authStateProvider = authStateProvider;

        // Initialize Firebase Auth Client
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

    public async Task<bool> SignInWithEmailAndPasswordAsync(string email, string password)
    {
        try
        {
            var userCredential = await _firebaseAuthClient.SignInWithEmailAndPasswordAsync(email, password);
            
            // Set auth cookie with the Firebase ID token
            await SetAuthCookie(userCredential.User.Credential.IdToken);
            
            return true;
        }
        catch (FirebaseAuthException ex)
        {
            _logger.LogWarning("Firebase authentication failed: {Error}", ex.Message);
            return false;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error signing in with email and password");
            return false;
        }
    }

    public async Task<bool> CreateUserWithEmailAndPasswordAsync(string email, string password)
    {
        try
        {
            var userCredential = await _firebaseAuthClient.CreateUserWithEmailAndPasswordAsync(email, password);
            
            // Set auth cookie with the Firebase ID token
            await SetAuthCookie(userCredential.User.Credential.IdToken);
            
            return true;
        }
        catch (FirebaseAuthException ex) when (ex.Reason == AuthErrorReason.EmailExists)
        {
            _logger.LogWarning("Email already exists: {Email}", email);
            return false;
        }
        catch (FirebaseAuthException ex)
        {
            _logger.LogError(ex, "Firebase authentication error creating user: {Email}", email);
            return false;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error creating user with email and password");
            return false;
        }
    }

    private async Task SetAuthCookie(string token)
    {
        try
        {
            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.NameIdentifier, token),
                new Claim(ClaimTypes.AuthenticationMethod, "Firebase")
            };

            var identity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
            var principal = new ClaimsPrincipal(identity);

            _authStateProvider.SetUser(principal);
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
            var token = user.FindFirst(ClaimTypes.NameIdentifier)?.Value;
            if (string.IsNullOrEmpty(token))
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

    public void SignOut()
    {
        try
        {
            _firebaseAuthClient.SignOut();
            _authStateProvider.SetUser(new ClaimsPrincipal(new ClaimsIdentity()));
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error signing out");
            throw;
        }
    }
}