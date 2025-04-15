using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using System.Threading.Tasks;
using System.Web;
using Zynapse.Blazor.Server.Services;

namespace Zynapse.Blazor.Server.Endpoints;

public static class AuthEndpoints
{
    public static void MapAuthEndpoints(this IEndpointRouteBuilder endpoints)
    {
        var group = endpoints.MapGroup("/api/auth");

        group.MapPost("/register", async (
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

        group.MapPost("/login", async (
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

        group.MapPost("/logout", async (HttpContext context) =>
        {
            await context.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            return Results.Redirect("/");
        });
    }
} 