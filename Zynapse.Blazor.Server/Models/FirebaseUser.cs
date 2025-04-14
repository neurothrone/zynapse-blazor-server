namespace Zynapse.Blazor.Server.Models
{
    public class FirebaseUser
    {
        public string Uid { get; set; } = string.Empty;
        public string? Email { get; set; }
        public string? DisplayName { get; set; }
        public DateTime? LastSignInTimestamp { get; set; }
        public bool EmailVerified { get; set; }
    }
} 