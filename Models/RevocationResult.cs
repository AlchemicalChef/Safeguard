using System;
using System.Collections.Generic;

namespace EntraTokenRevocationGUI.Models;

public class RevocationResult
{
    public bool Success { get; set; }
    public string? UserId { get; set; }
    public string? UserPrincipalName { get; set; }
    public string? DisplayName { get; set; }
    public string? ErrorMessage { get; set; }
    public DateTime? RevocationTime { get; set; }
}

public class MassRevocationResult
{
    public int TotalProcessed { get; set; }
    public int SuccessCount { get; set; }
    public int FailureCount { get; set; }
    public TimeSpan Duration { get; set; }
    public List<RevocationResult> Results { get; set; } = new();
    public List<RevocationResult> FailedUsers { get; set; } = new();
}


public class MfaResetResult
{
    public bool Success { get; set; }
    public string? UserId { get; set; }
    public string? UserPrincipalName { get; set; }
    public string? DisplayName { get; set; }
    public string? ErrorMessage { get; set; }
    public DateTime? ResetTime { get; set; }
    public int MethodsRemoved { get; set; }
    public List<string> RemovedMethodTypes { get; set; } = new();
}

public class MassMfaResetResult
{
    public int TotalProcessed { get; set; }
    public int SuccessCount { get; set; }
    public int FailureCount { get; set; }
    public int TotalMethodsRemoved { get; set; }
    public TimeSpan Duration { get; set; }
    public List<MfaResetResult> Results { get; set; } = new();
    public List<MfaResetResult> FailedUsers { get; set; } = new();
}

public class AuthMethodInfo
{
    public string? Id { get; set; }
    public string? MethodType { get; set; }
    public string? DisplayName { get; set; }
}

public class EnterpriseAppInfo
{
    public string? ApplicationId { get; set; }
    public string? ObjectId { get; set; }
    public string? DisplayName { get; set; }
    public string? ServicePrincipalId { get; set; }
    public DateTime? CreatedDateTime { get; set; }
    public List<string> Tags { get; set; } = new();
}

public class AppCleanupResult
{
    public bool Success { get; set; }
    public string? ApplicationId { get; set; }
    public string? DisplayName { get; set; }
    public string? ErrorMessage { get; set; }
    public bool ServicePrincipalDeleted { get; set; }
    public bool ApplicationDeleted { get; set; }
    public DateTime? CleanupTime { get; set; }
}

public class MassAppCleanupResult
{
    public int TotalProcessed { get; set; }
    public int SuccessCount { get; set; }
    public int FailureCount { get; set; }
    public int ServicePrincipalsDeleted { get; set; }
    public int ApplicationsDeleted { get; set; }
    public TimeSpan Duration { get; set; }
    public List<AppCleanupResult> Results { get; set; } = new();
    public List<AppCleanupResult> FailedApps { get; set; } = new();
}

public class EnterpriseAppViewModel
{
    public string? Id { get; set; }
    public string? AppId { get; set; }
    public string? DisplayName { get; set; }
    public DateTime? CreatedDateTime { get; set; }
    public string? PublisherName { get; set; }
    public bool IsSelected { get; set; }
}

public class FindingViewModel
{
    public string Id { get; set; } = string.Empty;
    public string Type { get; set; } = string.Empty;
    public string Severity { get; set; } = string.Empty;
    public string Title { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public string? AffectedResource { get; set; }
    public string? ResourceId { get; set; }
    public string Recommendation { get; set; } = string.Empty;
    public string MitreAttackTechnique { get; set; } = string.Empty;
    public Dictionary<string, string> Details { get; set; } = new();
}
