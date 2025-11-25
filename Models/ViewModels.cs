using System;
using System.Collections.Generic;
using Avalonia.Media;

namespace Safeguard.Models;

/// <summary>
/// Options for backdoor detection scan
/// </summary>
public class BackdoorScanOptions
{
    public bool ScanFederatedDomains { get; set; } = true;
    public bool ScanPTAAgents { get; set; } = true;
    public bool ScanServicePrincipals { get; set; } = true;
    public bool ScanOAuthGrants { get; set; } = true;
    public bool ScanAppCredentials { get; set; } = true;
    public bool ScanSyncConfiguration { get; set; } = true;
    public bool ScanFederatedIdentityCredentials { get; set; } = true;
    public bool ScanCrossTenantAccess { get; set; } = true;
    public bool ScanGuestAdmins { get; set; } = true;
}
