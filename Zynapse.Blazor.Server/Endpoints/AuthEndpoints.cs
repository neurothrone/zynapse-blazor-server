using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Mvc;
using System.Web;
using Zynapse.Blazor.Server.Services;
using Zynapse.Blazor.Server.Models;

namespace Zynapse.Blazor.Server.Endpoints;

public static class AuthEndpoints
{
    public static void MapAuthEndpoints(this IEndpointRouteBuilder endpoints)
    {
        var group = endpoints.MapGroup("/api/auth");

        group.MapPost("/register", async (
            HttpContext context,
            IAntiforgery antiforgery,
            FirebaseAuthService authService,
            [FromForm] RegisterModel model) =>
        {
            try
            {
                await antiforgery.ValidateRequestAsync(context);
            }
            catch (AntiforgeryValidationException)
            {
                return Results.Redirect("/register?error=Invalid+or+missing+antiforgery+token");
            }

            if (string.IsNullOrEmpty(model.Email) || string.IsNullOrEmpty(model.Password) || string.IsNullOrEmpty(model.ConfirmPassword))
            {
                return Results.Redirect("/register?error=Email,+password,+and+confirm+password+are+required");
            }

            if (model.Password != model.ConfirmPassword)
            {
                return Results.Redirect("/register?error=Passwords+do+not+match");
            }

            var (success, errorMessage) = 
                await authService.CreateUserWithEmailAndPasswordAsync(model.Email, model.Password);

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
            FirebaseAuthService authService,
            [FromForm] LoginModel model) =>
        {
            try
            {
                await antiforgery.ValidateRequestAsync(context);
            }
            catch (AntiforgeryValidationException)
            {
                return Results.Redirect("/login?error=Invalid+or+missing+antiforgery+token");
            }

            if (string.IsNullOrEmpty(model.Email) || string.IsNullOrEmpty(model.Password))
            {
                return Results.Redirect("/login?error=Email+and+password+are+required");
            }

            var (success, errorMessage) =
                await authService.SignInWithEmailAndPasswordAsync(model.Email, model.Password);

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