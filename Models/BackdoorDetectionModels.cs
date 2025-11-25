using System;
using System.Collections.Generic;

namespace Safeguard.Models;

/// <summary>
/// Represents a potential backdoor finding in the Entra ID tenant
/// Based on:
/// - Mandiant: https://cloud.google.com/blog/topics/threat-intelligence/detecting-microsoft-365-azure-active-directory-backdoors
/// - AADInternals: https://aadinternals.com/talks/
/// </summary>
public class BackdoorFinding
{
    public string Id { get; set; } = Guid.NewGuid().ToString();
    public BackdoorType Type { get; set; }
    public SeverityLevel Severity { get; set; }
    public string Title { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public string? AffectedResource { get; set; }
    public string? ResourceId { get; set; }
    public string? ResourceName { get; set; }
    public string? TechnicalDetails { get; set; }
    public bool CanRemediate { get; set; }
    public DateTime DetectedAt { get; set; } = DateTime.UtcNow;
    public Dictionary<string, string> Details { get; set; } = new();
    public string Recommendation { get; set; } = string.Empty;
    public string MitreAttackId { get; set; } = string.Empty;
}

public enum BackdoorType
{
    // Existing types
    FederatedDomainBackdoor,
    PassThroughAuthenticationAgent,
    SuspiciousServicePrincipal,
    HighPrivilegeOAuthGrant,
    RecentDomainAuthenticationChange,
    SuspiciousAppRegistration,
    AdminConsentGrant,
    SuspiciousCredential,
    UnknownPTAAgent,
    
    // AADInternals hybrid identity types
    EntraConnectSyncBackdoor,
    EntraCloudSyncBackdoor,
    SoftMatchEnabled,
    HardMatchEnabled,
    FederationMfaBypass,
    FederationValidationDisabled,
    SecondarySigningCertificate,
    SuspiciousSigningCertificate,
    ADFSTokenSigningExposed,
    SyncServiceAccountCompromise,
    CloudSyncAgentBackdoor,
    PrivilegedSyncAccount,
    DirectorySyncFeatureMisconfiguration,
    
    FociTokenAbuse,
    SeamlessSsoBackdoor,
    RogueDeviceRegistration,
    SuspiciousRedirectUri,
    ImplicitFlowEnabled,
    PublicClientWithSecrets,
    RefreshTokenReplay,
    PrimaryRefreshTokenTheft,
    
    FederatedIdentityCredentialBackdoor,
    FederatedIdentityCredentialMisconfigured,
    FederatedIdentityCredentialUnknownIssuer,
    
    DelegatedAdminRelationship,
    LegacyDelegatedAdminPermissions,
    CrossTenantAccessTrustMfa,
    CrossTenantAccessTrustDevice,
    CrossTenantAccessTrustHybridJoin,
    CrossTenantSyncEnabled,
    GuestUserWithAdminRole,
    CertificateBasedAuthNoCrl,
    PrivilegedGuestUser
}

/// <summary>
/// Domain information including federation settings
/// </summary>
public class DomainInfo
{
    public string? Id { get; set; }
    public string? DomainName { get; set; }
    public string? AuthenticationType { get; set; } // Managed or Federated
    public bool IsDefault { get; set; }
    public bool IsVerified { get; set; }
    public bool IsRoot { get; set; }
    public DateTime? CreatedDateTime { get; set; }
    
    // Federation details (if federated)
    public string? FederationBrandName { get; set; }
    public string? IssuerUri { get; set; }
    public string? MetadataExchangeUri { get; set; }
    public string? PassiveSignInUri { get; set; }
    public string? SigningCertificate { get; set; }
    public DateTime? SigningCertificateExpiry { get; set; }
}

/// <summary>
/// Pass-through authentication agent information
/// </summary>
public class PTAAgentInfo
{
    public string? Id { get; set; }
    public string? MachineName { get; set; }
    public string? ExternalIp { get; set; }
    public string? Status { get; set; }
    public DateTime? LastSeen { get; set; }
    public bool IsSuspicious { get; set; }
    public string? SuspicionReason { get; set; }
}

/// <summary>
/// Service principal with high-privilege permissions
/// </summary>
public class HighPrivilegeServicePrincipal
{
    public string? Id { get; set; }
    public string? AppId { get; set; }
    public string? DisplayName { get; set; }
    public DateTime? CreatedDateTime { get; set; }
    public string? PublisherName { get; set; }
    public bool IsFirstPartyApp { get; set; }
    public List<string> DangerousPermissions { get; set; } = new();
    public List<OAuthGrantInfo> AdminConsentGrants { get; set; } = new();
    public List<AppCredentialInfo> Credentials { get; set; } = new();
}

/// <summary>
/// OAuth2 permission grant information
/// </summary>
public class OAuthGrantInfo
{
    public string? Id { get; set; }
    public string? ClientAppId { get; set; }
    public string? ClientAppName { get; set; }
    public string? ResourceAppId { get; set; }
    public string? ResourceAppName { get; set; }
    public string? ConsentType { get; set; } // AllPrincipals = Admin consent
    public string? Scope { get; set; }
    public DateTime? GrantedDateTime { get; set; }
}

/// <summary>
/// App credential (secret/certificate) information
/// </summary>
public class AppCredentialInfo
{
    public string? KeyId { get; set; }
    public string? Type { get; set; } // Password or Certificate
    public string? DisplayName { get; set; }
    public DateTime? StartDateTime { get; set; }
    public DateTime? EndDateTime { get; set; }
    public bool IsExpired { get; set; }
    public bool NeverExpires { get; set; }
}

/// <summary>
/// Results from a backdoor detection scan
/// </summary>
public class BackdoorScanResult
{
    public DateTime ScanStartTime { get; set; }
    public DateTime ScanEndTime { get; set; }
    public TimeSpan Duration => ScanEndTime - ScanStartTime;
    
    public TimeSpan ScanDuration => Duration;
    
    public int TotalFindingsCount => Findings.Count;
    public int CriticalCount { get; set; }
    public int HighCount { get; set; }
    public int MediumCount { get; set; }
    public int LowCount { get; set; }
    
    public List<BackdoorFinding> Findings { get; set; } = new();
    
    // Scanned resources
    public int DomainsScanned { get; set; }
    public int ServicePrincipalsScanned { get; set; }
    public int OAuthGrantsScanned { get; set; }
    public int PTAAgentsScanned { get; set; }
    
    // Errors during scan
    public List<string> Errors { get; set; } = new();
    public bool CompletedSuccessfully => Errors.Count == 0;
}

/// <summary>
/// Result of revoking a federated domain backdoor
/// </summary>
public class FederationRevocationResult
{
    public bool Success { get; set; }
    public string DomainId { get; set; } = string.Empty;
    public string? FederationConfigId { get; set; }
    public string Message { get; set; } = string.Empty;
    public string? ErrorDetails { get; set; }
    public DateTime RevokedAt { get; set; } = DateTime.UtcNow;
    public bool ConvertedToManaged { get; set; }
}

/// <summary>
/// Entra Connect Sync configuration information
/// </summary>
public class EntraConnectSyncInfo
{
    public string? TenantId { get; set; }
    public bool OnPremisesSyncEnabled { get; set; }
    public DateTime? LastSyncTime { get; set; }
    public DateTime? LastPasswordSyncTime { get; set; }
    public string? SyncClientVersion { get; set; }
    
    // Sync features that can be abused
    public bool SoftMatchEnabled { get; set; }
    public bool HardMatchEnabled { get; set; }
    public bool PasswordHashSyncEnabled { get; set; }
    public bool PassThroughAuthEnabled { get; set; }
    public bool SeamlessSsoEnabled { get; set; }
    public bool UnifiedGroupWritebackEnabled { get; set; }
    public bool UserWritebackEnabled { get; set; }
    public bool DeviceWritebackEnabled { get; set; }
    public bool DirectoryExtensionsEnabled { get; set; }
    public bool BlockCloudObjectTakeoverEnabled { get; set; }
    public bool BlockSoftMatchEnabled { get; set; }
    
    // Service account info
    public string? SyncServiceAccountName { get; set; }
    public string? SyncServiceAccountType { get; set; } // User or Application
    public DateTime? SyncServiceAccountCreated { get; set; }
    public List<string> SyncServiceAccountRoles { get; set; } = new();
}

/// <summary>
/// Cloud Sync agent information
/// </summary>
public class CloudSyncAgentInfo
{
    public string? Id { get; set; }
    public string? MachineName { get; set; }
    public string? ExternalIp { get; set; }
    public string? Status { get; set; }
    public string? Version { get; set; }
    public DateTime? CreatedDateTime { get; set; }
    public DateTime? LastSeen { get; set; }
    public bool IsSuspicious { get; set; }
    public List<string> SuspicionReasons { get; set; } = new();
}

/// <summary>
/// Federation security configuration analysis
/// </summary>
public class FederationSecurityConfig
{
    public string? DomainId { get; set; }
    public string? IssuerUri { get; set; }
    
    // Security settings from AADInternals research
    public string? FederatedIdpMfaBehavior { get; set; } // Should be "rejectMfaByFederatedIdp"
    public string? PromptLoginBehavior { get; set; }
    public bool IsSignedAuthenticationRequestRequired { get; set; }
    
    // Certificate analysis
    public string? SigningCertificateThumbprint { get; set; }
    public DateTime? SigningCertificateNotBefore { get; set; }
    public DateTime? SigningCertificateNotAfter { get; set; }
    public string? SigningCertificateSubject { get; set; }
    public string? SigningCertificateIssuer { get; set; }
    public bool HasSecondarySigningCertificate { get; set; }
    public string? SecondarySigningCertificateThumbprint { get; set; }
    
    // Validation policy
    public bool ValidatingDomainsConfigured { get; set; }
    public List<string> ValidatingDomains { get; set; } = new();
    
    // Risk indicators
    public List<string> SecurityIssues { get; set; } = new();
}

/// <summary>
/// Token/credential theft indicators
/// </summary>
public class TokenTheftIndicator
{
    public string? UserId { get; set; }
    public string? UserPrincipalName { get; set; }
    public string? IndicatorType { get; set; } // PRT, RefreshToken, SessionCookie, etc.
    public DateTime? DetectedAt { get; set; }
    public string? SourceIp { get; set; }
    public string? UserAgent { get; set; }
    public string? Description { get; set; }
    public string MitreAttackId { get; set; } = string.Empty;
}

/// <summary>
/// Extended scan result with hybrid identity checks
/// </summary>
public class ExtendedBackdoorScanResult : BackdoorScanResult
{
    // Hybrid identity scan results
    public EntraConnectSyncInfo? SyncConfiguration { get; set; }
    public List<CloudSyncAgentInfo> SyncAgents { get; set; } = new(); // Initialize SyncAgents to prevent null reference
    public List<FederationSecurityConfig> FederationConfigs { get; set; } = new();
    
    // Additional counts
    public int SyncAgentsScanned { get; set; }
    public int FederationConfigsAnalyzed { get; set; }
    
    // Hybrid-specific findings summary
    public int HybridIdentityIssues { get; set; }
    public int FederationSecurityIssues { get; set; }
    public int SyncConfigurationIssues { get; set; }
}

/// <summary>
/// Known legitimate Microsoft first-party app IDs
/// These should not be flagged as suspicious
/// </summary>
public static class KnownMicrosoftApps
{
    public static readonly HashSet<string> FirstPartyAppIds = new(StringComparer.OrdinalIgnoreCase)
    {
        "00000002-0000-0000-c000-000000000000", // Azure Active Directory Graph
        "00000003-0000-0000-c000-000000000000", // Microsoft Graph
        "00000001-0000-0000-c000-000000000000", // Azure ESTS Service
        "00000002-0000-0ff1-ce00-000000000000", // Office 365 Exchange Online
        "00000003-0000-0ff1-ce00-000000000000", // Office 365 SharePoint Online
        "00000004-0000-0ff1-ce00-000000000000", // Skype for Business Online
        "00000006-0000-0ff1-ce00-000000000000", // Microsoft Office 365 Portal
        "00000007-0000-0ff1-ce00-000000000000", // Microsoft Office 365 Admin Portal
        "00000009-0000-0000-c000-000000000000", // Microsoft Power BI Service
        "0000000c-0000-0000-c000-000000000000", // Microsoft App Access Panel
        "797f4846-ba00-4fd7-ba43-dac1f8f63013", // Windows Azure Service Management API
        "c5393580-f805-4401-95e8-94b7a6ef2fc2", // Office 365 Management APIs
        "fc780465-2017-40d4-a0c5-307022471b92", // Microsoft Intune
        "d3590ed6-5e6e-4d8a-9f3d-ecd601259da7", // Microsoft Office
        "1fec8e78-bce4-4aaf-ab1b-5451cc387264", // Microsoft Teams
        "cc15fd57-2c6c-4117-a88c-83b1d56b4bbe", // Microsoft Teams Services
        "5e3ce6c0-2b1f-4285-8d4b-75ee78787346", // Microsoft Teams Web Client
        "89bee1f7-5e6e-4b7e-9f3d-dac224a7b894", // Office 365 Exchange Online Protection
        "00000012-0000-0000-c000-000000000000", // Yammer
        "00000015-0000-0000-c000-000000000000", // Microsoft Dynamics CRM
        "00000016-0000-0000-c000-000000000000", // Microsoft Azure Active Directory
        "00000007-0000-0000-c000-000000000000", // Dynamics CRM Online
        "7ab7862c-4c57-491e-8a45-d52a7e023983", // App Service
        "0000001a-0000-0000-c000-000000000000", // MicrosoftAzureActiveAuthn
        "cb1056e2-e479-49de-ae31-7812af012ed8", // Azure Portal
        "1b730954-1685-4b74-9bfd-dac224a7b894", // Azure Active Directory PowerShell
        "04b07795-8ddb-461a-bbee-02f9e1bf7b46", // Microsoft Azure CLI
        "18fbca16-2224-45f6-85b0-f7bf2b39b3f3", // Microsoft Docs
        "871c010f-5e61-4fb1-83ac-974e53cbdf3c", // Azure AD Sync
        "6eb59a73-39b2-4c23-a70f-e2e3ce8965b1", // AAD Sync Service
        "cb3d0662-bb62-4769-bfbd-2e7efcc16f22", // Microsoft Entra Cloud Sync
    };

    /// <summary>
    /// Known sync service account patterns
    /// </summary>
    public static readonly HashSet<string> SyncServiceAccountPatterns = new(StringComparer.OrdinalIgnoreCase)
    {
        "Sync_",                    // Default Entra Connect sync account prefix
        "ADToAADSyncServiceAccount", // Cloud Sync service account
        "AAD_",                     // Legacy AAD Connect prefix
        "MSOL_",                    // Legacy MSOL prefix
        "On-Premises Directory Synchronization Service Account"
    };
    
    /// <summary>
    /// Dangerous sync-related roles
    /// </summary>
    public static readonly HashSet<string> DangerousSyncRoles = new(StringComparer.OrdinalIgnoreCase)
    {
        "Directory Synchronization Accounts",
        "Directory Writers",
        "Hybrid Identity Administrator",
        "Global Administrator",
        "Privileged Authentication Administrator"
    };
    
    /// <summary>
    /// High-risk permissions that should trigger alerts
    /// </summary>
    public static readonly HashSet<string> DangerousPermissions = new(StringComparer.OrdinalIgnoreCase)
    {
        "Directory.ReadWrite.All",
        "RoleManagement.ReadWrite.Directory",
        "Application.ReadWrite.All",
        "AppRoleAssignment.ReadWrite.All",
        "User.ReadWrite.All",
        "Group.ReadWrite.All",
        "Mail.ReadWrite",
        "Mail.Send",
        "Files.ReadWrite.All",
        "Sites.ReadWrite.All",
        "Policy.ReadWrite.ConditionalAccess",
        "Policy.ReadWrite.TrustFramework",
        "TrustFrameworkKeySet.ReadWrite.All",
        "UserAuthenticationMethod.ReadWrite.All",
        "DelegatedPermissionGrant.ReadWrite.All",
        "full_access_as_app", // Exchange full access
        "Exchange.ManageAsApp",
        "Domain.ReadWrite.All",
        "Organization.ReadWrite.All",
        "OnPremDirectorySynchronization.ReadWrite.All",
        "OnPremisesPublishingProfiles.ReadWrite.All",
        "Directory.AccessAsUser.All",
        "PrivilegedAccess.ReadWrite.AzureAD",
        "PrivilegedAccess.ReadWrite.AzureResources",
    };
    
    /// <summary>
    /// Suspicious issuer URI patterns indicating potential backdoors
    /// </summary>
    public static readonly HashSet<string> SuspiciousIssuerPatterns = new(StringComparer.OrdinalIgnoreCase)
    {
        "localhost",
        "127.0.0.1",
        "192.168.",
        "10.0.",
        "10.1.",
        "172.16.",
        "172.17.",
        "172.18.",
        "172.19.",
        "172.20.",
        "172.21.",
        "172.22.",
        "172.23.",
        "172.24.",
        "172.25.",
        "172.26.",
        "172.27.",
        "172.28.",
        "172.29.",
        "172.30.",
        "172.31.",
        "aadinternals",
        "azuread-sso",
        ".local",
        ".internal",
        "test.",
        "dev.",
        "temp.",
    };
}

/// <summary>
/// FOCI (Family of Client IDs) - Apps that share refresh tokens
/// These are Microsoft first-party apps that can exchange tokens
/// Attackers can abuse stolen refresh tokens across these apps
/// </summary>
public static class FociClientIds
{
    /// <summary>
    /// Known Microsoft FOCI family apps that share refresh tokens
    /// A refresh token from one can be exchanged for tokens to another
    /// </summary>
    public static readonly Dictionary<string, string> FociApps = new(StringComparer.OrdinalIgnoreCase)
    {
        { "1fec8e78-bce4-4aaf-ab1b-5451cc387264", "Microsoft Teams" },
        { "d3590ed6-52b3-4102-aeff-aad2292ab01c", "Microsoft Office" },
        { "a0c73c16-a7e3-4564-9a95-2bdf47383716", "Microsoft Exchange REST API" },
        { "9ba1a5c7-f17a-4de9-a1f1-6178c8d51223", "Microsoft Intune Portal" },
        { "1b730954-1685-4b74-9bfd-dac224a7b894", "Azure AD PowerShell" },
        { "04b07795-8ddb-461a-bbee-02f9e1bf7b46", "Azure CLI" },
        { "00000002-0000-0000-c000-000000000000", "Azure AD Graph" },
        { "00000003-0000-0000-c000-000000000000", "Microsoft Graph" },
        { "26a7ee05-5602-4d76-a7ba-eae8b7b67941", "Windows Search" },
        { "27922004-5251-4030-b22d-91ecd9a37ea4", "Outlook Mobile" },
        { "4813382a-8fa7-425e-ab75-3b753aab3abb", "Microsoft Authenticator" },
        { "ab9b8c07-8f02-4f72-87fa-80105867a763", "OneDrive SyncEngine" },
        { "d326c1ce-6cc6-4de2-bebc-4591e5e13ef0", "SharePoint" },
        { "e9c51622-460d-4d3d-952d-966a5b1da34c", "Microsoft Edge" },
        { "ecd6b820-32c2-49b6-98a6-444530e5a77a", "Microsoft Edge (Legacy)" },
        { "f44b1140-bc5e-48c6-8dc0-5cf5a53c0e34", "Microsoft Edge Insider" },
        { "2d7f3606-b07d-41d1-b9d2-0d0c9296a6e8", "Microsoft Bing Search" },
        { "57336123-6e14-4acc-8dcf-287b6088aa28", "Microsoft Whiteboard" },
        { "66375f6b-983f-4c2c-9701-d680650f588f", "Microsoft Planner" },
        { "de8bc8b5-d9f9-48b1-a8ad-b748da725064", "Microsoft To-Do" },
        { "ab936c11-f0eb-4e40-87b8-ed9d272e3ce8", "OneDrive iOS" },
        { "af124e86-4e96-495a-b70a-90f90ab96707", "OneDrive for Business" },
        { "dd47d17a-3194-4d86-bfd5-c6ae6f5651e3", "Microsoft Stream Mobile" },
    };
    
    /// <summary>
    /// Dangerous FOCI scenarios - apps that shouldn't have certain permissions together
    /// </summary>
    public static readonly HashSet<string> HighRiskFociScopes = new(StringComparer.OrdinalIgnoreCase)
    {
        "Mail.ReadWrite",
        "Mail.Send",
        "Files.ReadWrite.All",
        "User.ReadWrite.All",
        "Directory.ReadWrite.All",
        "offline_access" // Required for refresh tokens
    };
}

/// <summary>
/// Suspicious redirect URI patterns that indicate potential token theft
/// </summary>
public static class SuspiciousRedirectPatterns
{
    public static readonly List<string> DangerousPatterns = new()
    {
        "http://localhost",           // Local interception
        "http://127.0.0.1",           // Local interception
        "http://[::1]",               // IPv6 localhost
        "urn:ietf:wg:oauth:2.0:oob",  // Legacy native app flow
        "ms-appx-web://",             // Can be hijacked on Windows
        "javascript:",                // XSS vector
        "data:",                      // Data URI injection
        "file://",                    // Local file access
        "http://",                    // Non-HTTPS (token in clear)
        ".ngrok.io",                  // Tunneling service
        ".serveo.net",                // Tunneling service
        ".localtunnel.me",            // Tunneling service
        ".burpcollaborator.net",      // Pentesting tool
        ".oastify.com",               // OAST tool
        ".interact.sh",               // OAST tool
    };
    
    public static readonly List<string> HighRiskButLegitimate = new()
    {
        "https://login.microsoftonline.com", // Token broker
        "https://login.windows.net",          // Legacy login
        "https://portal.azure.com",           // Azure portal
        "https://www.office.com",             // Office portal
    };
}

/// <summary>
/// Device registration information for PRT theft detection
/// </summary>
public class DeviceRegistrationInfo
{
    public string? DeviceId { get; set; }
    public string? DisplayName { get; set; }
    public string? OperatingSystem { get; set; }
    public string? OperatingSystemVersion { get; set; }
    public string? TrustType { get; set; } // AzureAD, ServerAD, Workplace
    public DateTime? RegistrationDateTime { get; set; }
    public DateTime? ApproximateLastSignInDateTime { get; set; }
    public bool IsCompliant { get; set; }
    public bool IsManaged { get; set; }
    public string? MdmAppId { get; set; }
    public List<string> AlternativeSecurityIds { get; set; } = new();
    
    // Risk indicators
    public bool IsRecentlyRegistered => RegistrationDateTime > DateTime.UtcNow.AddDays(-7);
    public bool HasSuspiciousName { get; set; }
    public bool IsOrphaned { get; set; } // No recent sign-in
    public List<string> RiskIndicators { get; set; } = new();
}

/// <summary>
/// Seamless SSO configuration for AZUREADSSOACC backdoor detection
/// </summary>
public class SeamlessSsoInfo
{
    public bool IsEnabled { get; set; }
    public string? ComputerAccountName { get; set; } // Should be AZUREADSSOACC
    public DateTime? PasswordLastSet { get; set; }
    public int PasswordAgeInDays => PasswordLastSet.HasValue 
        ? (int)(DateTime.UtcNow - PasswordLastSet.Value).TotalDays 
        : -1;
    public bool PasswordNeverRotated => PasswordAgeInDays > 30; // Should rotate frequently
    public List<string> EnabledDomains { get; set; } = new();
    public List<string> RiskIndicators { get; set; } = new();
}

/// <summary>
/// App registration security analysis
/// </summary>
public class AppSecurityAnalysis
{
    public string? AppId { get; set; }
    public string? DisplayName { get; set; }
    public string? SignInAudience { get; set; } // AzureADMyOrg, AzureADMultipleOrgs, etc.
    
    // OAuth flow analysis
    public bool ImplicitFlowEnabled { get; set; }
    public bool ImplicitIdTokenEnabled { get; set; }
    public bool ImplicitAccessTokenEnabled { get; set; }
    public bool PublicClientEnabled { get; set; }
    public bool HasClientSecrets { get; set; }
    public bool HasCertificates { get; set; }
    
    // Redirect URI analysis
    public List<string> RedirectUris { get; set; } = new();
    public List<string> SuspiciousRedirectUris { get; set; } = new();
    public bool HasHttpRedirectUri { get; set; }
    public bool HasLocalhostRedirectUri { get; set; }
    public bool HasWildcardRedirectUri { get; set; }
    
    // Permission analysis
    public List<string> RequiredResourceAccess { get; set; } = new();
    public bool IsFociMember { get; set; }
    
    // Risk summary
    public List<string> SecurityIssues { get; set; } = new();
    public SeverityLevel OverallRisk { get; set; }
}

/// <summary>
/// Unified SeverityLevel enum - removed duplicate, using consistent values
/// </summary>
public enum SeverityLevel
{
    Info,
    Low,
    Medium,
    High,
    Critical
}
