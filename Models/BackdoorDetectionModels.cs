using System;
using System.Collections.Generic;

namespace EntraTokenRevocationGUI.Models;

/// <summary>
/// Represents a potential backdoor finding in the Entra ID tenant
/// Based on Mandiant's research: https://cloud.google.com/blog/topics/threat-intelligence/detecting-microsoft-365-azure-active-directory-backdoors
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
    public DateTime DetectedAt { get; set; } = DateTime.UtcNow;
    public Dictionary<string, string> Details { get; set; } = new();
    public string Recommendation { get; set; } = string.Empty;
    public string MitreAttackTechnique { get; set; } = string.Empty;
}

public enum BackdoorType
{
    FederatedDomainBackdoor,
    PassThroughAuthenticationAgent,
    SuspiciousServicePrincipal,
    HighPrivilegeOAuthGrant,
    RecentDomainAuthenticationChange,
    SuspiciousAppRegistration,
    AdminConsentGrant,
    SuspiciousCredential,
    UnknownPTAAgent
}

public enum SeverityLevel
{
    Critical,
    High,
    Medium,
    Low,
    Informational
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
        "d3590ed6-52b3-4102-aeff-aad2292ab01c", // Microsoft Office
        "1fec8e78-bce4-4aaf-ab1b-5451cc387264", // Microsoft Teams
        "cc15fd57-2c6c-4117-a88c-83b1d56b4bbe", // Microsoft Teams Services
        "5e3ce6c0-2b1f-4285-8d4b-75ee78787346", // Microsoft Teams Web Client
        "89bee1f7-5e6e-4d8a-9f3d-ecd601259da7", // Office 365 Exchange Online Protection
        "00000005-0000-0ff1-ce00-000000000000", // Yammer
        "00000012-0000-0000-c000-000000000000", // Microsoft Rights Management Services
        "00000015-0000-0000-c000-000000000000", // Microsoft Dynamics CRM
        "00000016-0000-0000-c000-000000000000", // Microsoft Azure Active Directory
        "00000007-0000-0000-c000-000000000000", // Dynamics CRM Online
        "7ab7862c-4c57-491e-8a45-d52a7e023983", // App Service
        "0000001a-0000-0000-c000-000000000000", // MicrosoftAzureActiveAuthn
        "cb1056e2-e479-49de-ae31-7812af012ed8", // Azure Portal
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
    };
}
