namespace EntraTokenRevocationGUI.Models;

public class AuthenticationResult
{
    public bool Success { get; set; }
    public string? UserId { get; set; }
    public string? UserPrincipalName { get; set; }
    public string? DisplayName { get; set; }
    public string? ErrorMessage { get; set; }
    public string? AuthMethod { get; set; }
}
