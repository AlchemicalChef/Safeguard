# Safeguard - Entra ID Incident Response Tool

A comprehensive WPF GUI application for incident response in Microsoft Entra ID environments. Safeguard enables security teams to quickly take back control during a security incident by revoking user tokens, resetting MFA, cleaning up compromised enterprise applications, detecting backdoors, and remediating risky accounts.

## Use Cases

- **Active Breach Response** - Immediately revoke all user sessions to force re-authentication
- **Compromised Account Containment** - Target specific users for token revocation
- **MFA Reset After Credential Theft** - Force users to re-register authentication methods
- **Malicious App Removal** - Delete rogue enterprise applications from your tenant
- **Backdoor Detection** - Scan for AADInternals attacks, rogue PTA agents, and suspicious OAuth grants
- **Password Hygiene Audits** - Identify risky accounts with never-set or stale passwords and remediate them
- **Post-Incident Recovery** - Systematically restore control of your Entra ID environment

## Features

- **Secure Authentication** - Resource Owner Password Credentials (ROPC) flow with username/password entry (no secrets stored locally)
- **Single User Revocation** - Look up and revoke tokens for individual users
- **Mass Token Revocation** - Bulk revoke all users except the signed-in administrator
- **Mass MFA Reset** - Remove all authentication methods for all users (except current user)
- **Enterprise App Cleanup** - Delete service principals and app registrations from your tenant
- **Backdoor Detection** - Comprehensive scan for known Entra ID persistence techniques
- **Risky Account Detection** - Scan all member accounts for never-set passwords, 1601 epoch timestamps, and aged credentials
- **Automated Remediation** - Force password reset and/or disable risky accounts directly from the UI
- **Activity Logging** - Real-time operation logging with JSON export capability
- **Throttling Awareness** - Visual banner and countdown when Microsoft Graph enforces rate limits
- **Safety Features** - Confirmation dialogs and current-user protection

## Backdoor Detection

Based on Mandiant's research, my own, and Microsoft's, Safeguard can detect:

| Backdoor Type | Detection Method | Severity |
|---------------|------------------|----------|
| Federation Backdoor | Analyzes federated domains for suspicious IssuerURIs, localhost references, or AADInternals signatures | Critical |
| Rogue PTA Agent | Identifies PTA agents from unknown/cloud provider IPs | Critical |
| High-Privilege App | Finds apps with Directory.ReadWrite.All, RoleManagement.ReadWrite.Directory, etc. | High |
| Admin Consent Attack | Detects admin consent grants for dangerous scopes | High |
| Suspicious Credentials | Identifies recently added or long-lived app secrets | Medium |

Each finding includes MITRE ATT&CK technique mapping and actionable remediation recommendations.

## Requirements

- Windows 10/11
- .NET 8.0 SDK
- JetBrains Rider 2023.3+ (or any compatible IDE)
- Microsoft Entra ID tenant with appropriate permissions

## Entra ID App Registration

1. Go to [Microsoft Entra admin center](https://entra.microsoft.com)
2. Navigate to **Identity** > **Applications** > **App registrations**
3. Click **New registration**
4. Configure:
   - **Name**: `Safeguard Incident Response`
   - **Supported account types**: `Accounts in this organizational directory only`
    - **Redirect URI**: Leave blank (not needed for ROPC)
5. After creation, go to **Authentication**:
   - Enable **Allow public client flows** > Set to **Yes** (required for ROPC)
6. Go to **API permissions** > **Add a permission** > **Microsoft Graph**:
   - Add **Delegated permissions**:
     - `User.Read` (for reading signed-in user)
     - `User.ReadWrite.All` (for revoking user sessions)
     - `Directory.ReadWrite.All` (for listing users and PTA agent detection)
     - `UserAuthenticationMethod.ReadWrite.All` (for MFA reset)
     - `Application.ReadWrite.All` (for enterprise app cleanup and backdoor detection)
   - Click **Grant admin consent** for your organization
7. Copy the **Application (client) ID** from the Overview page

## Setup in JetBrains Rider

### Opening the Project

1. Open JetBrains Rider
2. Select **File** > **Open**
3. Navigate to the `EntraTokenRevocationGUI` folder
4. Select `Safeguard.sln` and click **Open**
5. Rider will restore NuGet packages automatically

### First Run

1. Wait for NuGet package restoration to complete (check bottom status bar)
2. Press `Shift+F10` or click the green **Run** button
3. In the application:
   - Enter your **Client ID** from the app registration
   - Enter your **Tenant ID** (found in Entra admin center > Overview)
   - Enter a **username** and **password** that can use ROPC (no MFA or Conditional Access requiring interaction)
   - Click **Connect to Entra ID**
4. Safeguard will authenticate silently using the credentials and show connection status in the header

### Building

- **Debug Build**: `Ctrl+Shift+B` or **Build** > **Build Solution**
- **Release Build**: **Build** > **Build Solution** (after selecting Release configuration)

### Debugging

- Set breakpoints by clicking in the left margin
- Press `Shift+F9` to start debugging
- Use the **Debug** tool window to inspect variables


## Incident Response Workflows

### Scenario 1: Active Breach - Unknown Scope

1. Launch Safeguard and authenticate
2. Go to **Backdoor Detection** tab
3. Enter your organization's WAN IPs in "Known Internal IPs"
4. Run the full backdoor scan
5. Review Critical and High findings for immediate threats
6. Execute **Mass Token Revocation** to invalidate all sessions
7. Delete any suspicious applications identified

### Scenario 2: Suspected MFA Compromise

1. Launch Safeguard and authenticate
2. Run **Backdoor Detection** scan to check for OAuth consent attacks
3. Go to **Mass MFA Reset** tab
4. Review the list of authentication methods to be removed
5. Confirm both checkboxes and execute
6. Users will need to re-register MFA at next sign-in

### Scenario 2b: Risky Password Hygiene

1. Launch Safeguard and authenticate
2. Go to **Risky Accounts** tab
3. Click **Scan for Risky Accounts** to detect never-set or stale passwords
4. Select impacted accounts and choose **Force password reset** and/or **Disable account**
5. Click **Remediate Selected** to take action

### Scenario 3: Malicious App Detected

1. Launch Safeguard and authenticate
2. Run **Backdoor Detection** to find related applications
3. Go to **App Cleanup** tab
4. Click **Load Apps** to view all enterprise applications
5. Select the suspicious applications
6. Confirm and delete

### Scenario 4: Federation Backdoor (AADInternals)

1. Run **Backdoor Detection** scan
2. If suspicious federation found, note the domain name
3. Convert domain back to managed authentication:
   \`\`\`powershell
   Set-MsolDomainAuthentication -DomainName <domain> -Authentication Managed
   \`\`\`
4. Execute **Mass Token Revocation** to invalidate any tokens issued via malicious federation

### Scenario 5: Single Compromised Account

1. Launch Safeguard and authenticate
2. Go to **Single User** tab
3. Enter the user's email or Object ID
4. Click **Look Up** to verify the account
5. Click **Revoke User Tokens**

### Scenario 6: Graph Throttling During Response

1. Continue using Safeguard; if Microsoft Graph throttles requests, a banner appears showing the retry countdown
2. Wait for the cooldown to expire—the operation will automatically resume
3. Dismiss the banner if desired; throttling events are also logged in the activity feed

## Security Considerations

- **No secrets stored**: Uses ROPC with username/password entry—no client secrets written to disk
- **Admin consent required**: Permissions must be granted by a tenant admin
- **Current user protected**: Mass operations automatically exclude the signed-in user
- **Confirmation dialogs**: All destructive operations require explicit confirmation
- **Audit trail**: All operations are logged with timestamps

### Authentication Requirements

- The signed-in account must be allowed to use ROPC (no MFA prompts or interactive challenges)
- Public client flows must be enabled on the app registration
- Consider using a break-glass account reserved for emergency response scenarios

## API Permissions Explained

| Permission | Type | Purpose |
|------------|------|---------|
| `User.Read` | Delegated | Read signed-in user's profile |
| `User.ReadWrite.All` | Delegated | Revoke sign-in sessions for any user |
| `Directory.ReadWrite.All` | Delegated | List all users, detect PTA agents |
| `UserAuthenticationMethod.ReadWrite.All` | Delegated | Delete user authentication methods (MFA reset) |
| `Application.ReadWrite.All` | Delegated | Delete enterprise apps, scan for suspicious apps |

## Troubleshooting

### "NuGet packages not found"
- Right-click the solution > **Manage NuGet Packages**
- Click **Restore** or wait for automatic restoration

### "Permission denied" errors
- Ensure admin consent was granted for all API permissions
- Verify the signed-in user has appropriate Entra ID roles (Global Admin or Security Admin recommended)

### "Interactive authentication required" or "invalid_grant"
- The account may be protected by MFA or Conditional Access that blocks ROPC
- Use a break-glass account permitted for non-interactive sign-in or adjust policy scope
- Confirm the username and password are entered correctly

### WPF Designer not loading
- Close and reopen the XAML file
- Rebuild the solution: **Build** > **Rebuild Solution**

### MFA Reset rate limiting
- Use smaller batch sizes (10-20 users)
- Increase delay between batches to 2000ms or more
- MFA operations require multiple API calls per user

### "Insufficient privileges" for app cleanup
- Ensure `Application.ReadWrite.All` permission is granted
- Admin consent must be provided for this permission
- You must have Application Administrator or Global Administrator role

### App not appearing in list
- Click **Load Apps** to refresh the list
- The current application is intentionally excluded
- Only Application-type service principals are shown (not managed identities)

### Backdoor scan shows "Insufficient permissions"
- Ensure all API permissions are granted with admin consent
- PTA agent scanning requires `Directory.ReadWrite.All`
- Some features use beta API endpoints that may have limited availability

### PTA agent scan returns no results
- Pass-through Authentication might not be enabled in your tenant (this is normal)
- Enter your organization's WAN IPs to improve detection accuracy

## References

- [Mandiant: Detecting Microsoft 365 and Azure Active Directory Backdoors](https://cloud.google.com/blog/topics/threat-intelligence/detecting-microsoft-365-azure-active-directory-backdoors)
- [Microsoft Graph API: revokeSignInSessions](https://learn.microsoft.com/en-us/graph/api/user-revokesigninsessions)
- [Microsoft Graph API: Authentication Methods](https://learn.microsoft.com/en-us/graph/api/resources/authenticationmethods-overview)
- [MITRE ATT&CK: Modify Authentication Process](https://attack.mitre.org/techniques/T1556/)

## License

MIT License - See LICENSE file for details
