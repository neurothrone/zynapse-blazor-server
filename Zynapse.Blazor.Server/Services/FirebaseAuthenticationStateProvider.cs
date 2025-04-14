using Microsoft.AspNetCore.Components.Authorization;
using System.Security.Claims;

namespace Zynapse.Blazor.Server.Services;

public class FirebaseAuthenticationStateProvider : AuthenticationStateProvider
{
    private ClaimsPrincipal _anonymous = new ClaimsPrincipal(new ClaimsIdentity());
    private ClaimsPrincipal? _currentUser;

    public override Task<AuthenticationState> GetAuthenticationStateAsync()
    {
        return Task.FromResult(new AuthenticationState(_currentUser ?? _anonymous));
    }

    public void SetUser(ClaimsPrincipal? user)
    {
        _currentUser = user;
        NotifyAuthenticationStateChanged(GetAuthenticationStateAsync());
    }

    public void NotifyStateChanged()
    {
        NotifyAuthenticationStateChanged(GetAuthenticationStateAsync());
    }
} 