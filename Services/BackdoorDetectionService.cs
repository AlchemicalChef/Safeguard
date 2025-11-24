using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Graph;
using Microsoft.Graph.Models;
using EntraTokenRevocationGUI.Models;

namespace EntraTokenRevocationGUI.Services;

/// <summary>
/// Service for detecting Azure AD/Entra ID backdoors
/// Based on Mandiant's research: https://cloud.google.com/blog/topics/threat-intelligence/detecting-microsoft-365-azure-active-directory-backdoors
/// </summary>
public class BackdoorDetectionService
{
    private readonly AuthenticationService _authService;
    private readonly List<string> _knownInternalIps = new();

    public BackdoorDetectionService(AuthenticationService authService)
    {
        _authService = authService ?? throw new ArgumentNullException(nameof(authService));
    }

    private GraphServiceClient GraphClient => _authService.GraphClient;

    /// <summary>
    /// Set known internal IP addresses/ranges to exclude from PTA agent checks
    /// </summary>
    public void SetKnownInternalIps(IEnumerable<string> ips)
    {
        _knownInternalIps.Clear();
        _knownInternalIps.AddRange(ips);
    }

    /// <summary>
    /// Run a comprehensive backdoor detection scan
    /// </summary>
    public async Task<BackdoorScanResult> RunFullScanAsync(
        Action<string>? progressCallback = null,
        CancellationToken cancellationToken = default)
    {
        var result = new BackdoorScanResult
        {
            ScanStartTime = DateTime.UtcNow
        };

        try
        {
            // 1. Scan domains for federation backdoors
            progressCallback?.Invoke("Scanning domains for federation backdoors...");
            await ScanDomainsAsync(result, cancellationToken);

            // 2. Scan for suspicious service principals
            progressCallback?.Invoke("Scanning service principals for high-privilege permissions...");
            await ScanServicePrincipalsAsync(result, cancellationToken);

            // 3. Scan OAuth2 permission grants
            progressCallback?.Invoke("Scanning OAuth2 permission grants...");
            await ScanOAuthGrantsAsync(result, cancellationToken);

            // 4. Scan for Pass-through Authentication agents (requires beta API)
            progressCallback?.Invoke("Scanning for PTA agents...");
            await ScanPTAAgentsAsync(result, cancellationToken);

            // 5. Scan for suspicious app registrations with credentials
            progressCallback?.Invoke("Scanning app registrations for suspicious credentials...");
            await ScanAppRegistrationsAsync(result, cancellationToken);

            // Calculate severity counts
            result.CriticalCount = result.Findings.Count(f => f.Severity == SeverityLevel.Critical);
            result.HighCount = result.Findings.Count(f => f.Severity == SeverityLevel.High);
            result.MediumCount = result.Findings.Count(f => f.Severity == SeverityLevel.Medium);
            result.LowCount = result.Findings.Count(f => f.Severity == SeverityLevel.Low);
        }
        catch (Exception ex)
        {
            result.Errors.Add($"Scan error: {ex.Message}");
        }
        finally
        {
            result.ScanEndTime = DateTime.UtcNow;
        }

        return result;
    }

    #region Domain Scanning

    /// <summary>
    /// Scan domains for federation backdoors (Backdoor #2 from Mandiant article)
    /// </summary>
    private async Task ScanDomainsAsync(BackdoorScanResult result, CancellationToken cancellationToken)
    {
        try
        {
            var domains = await GraphClient.Domains.GetAsync(cancellationToken: cancellationToken);

            if (domains?.Value == null) return;

            result.DomainsScanned = domains.Value.Count;

            foreach (var domain in domains.Value)
            {
                cancellationToken.ThrowIfCancellationRequested();

                // Check for federated domains
                if (string.Equals(domain.AuthenticationType, "Federated", StringComparison.OrdinalIgnoreCase))
                {
                    // Get federation configuration
                    var federationConfig = await GetFederationConfigAsync(domain.Id!, cancellationToken);

                    if (federationConfig != null)
                    {
                        // Check for suspicious federation settings
                        var finding = AnalyzeFederatedDomain(domain, federationConfig);
                        if (finding != null)
                        {
                            // Store federation config ID in details for revocation
                            finding.Details["FederationConfigId"] = federationConfig.Id ?? "";
                            result.Findings.Add(finding);
                        }
                    }
                    else
                    {
                        // Federated domain without accessible config - suspicious
                        result.Findings.Add(new BackdoorFinding
                        {
                            Type = BackdoorType.FederatedDomainBackdoor,
                            Severity = SeverityLevel.High,
                            Title = $"Federated domain with inaccessible configuration: {domain.Id}",
                            Description = "A federated domain was found but its federation configuration could not be retrieved. This may indicate a malicious federation configuration using AADInternals ConvertTo-AADIntBackdoor.",
                            AffectedResource = domain.Id,
                            ResourceId = domain.Id,
                            Recommendation = "Verify this domain's federation settings in the Azure AD portal. Consider converting back to managed authentication if the federation is not legitimate.",
                            MitreAttackTechnique = "T1484.002 - Domain Trust Modification",
                            Details = new Dictionary<string, string>
                            {
                                ["DomainId"] = domain.Id ?? "",
                                ["AuthenticationType"] = "Federated",
                                ["FederationConfigId"] = ""
                            }
                        });
                    }
                }

                // Check for recently created domains (potential attacker-added domain)
                if (domain.State?.Status == "Verified")
                {
                    // Unfortunately Graph API doesn't expose domain creation date easily
                    // but we flag non-default verified domains for review
                    if (domain.IsDefault != true && domain.IsInitial != true)
                    {
                        result.Findings.Add(new BackdoorFinding
                        {
                            Type = BackdoorType.RecentDomainAuthenticationChange,
                            Severity = SeverityLevel.Informational,
                            Title = $"Non-default verified domain: {domain.Id}",
                            Description = "A verified custom domain was found. Ensure this domain is legitimate and was added by authorized personnel.",
                            AffectedResource = domain.Id,
                            ResourceId = domain.Id,
                            Recommendation = "Verify this domain was added intentionally and review its authentication configuration.",
                            MitreAttackTechnique = "T1484.002 - Domain Trust Modification"
                        });
                    }
                }
            }
        }
        catch (Exception ex)
        {
            result.Errors.Add($"Domain scan error: {ex.Message}");
        }
    }

    private async Task<InternalDomainFederation?> GetFederationConfigAsync(string domainId, CancellationToken cancellationToken)
    {
        try
        {
            var federationConfigs = await GraphClient.Domains[domainId].FederationConfiguration.GetAsync(cancellationToken: cancellationToken);
            return federationConfigs?.Value?.FirstOrDefault() as InternalDomainFederation;
        }
        catch
        {
            return null;
        }
    }

    private BackdoorFinding? AnalyzeFederatedDomain(Domain domain, InternalDomainFederation config)
    {
        var suspiciousIndicators = new List<string>();

        // Check for suspicious issuer URI patterns
        if (!string.IsNullOrEmpty(config.IssuerUri))
        {
            // Check if issuer doesn't match expected ADFS patterns
            if (!config.IssuerUri.Contains("adfs", StringComparison.OrdinalIgnoreCase) &&
                !config.IssuerUri.Contains("sts", StringComparison.OrdinalIgnoreCase) &&
                !config.IssuerUri.Contains("federation", StringComparison.OrdinalIgnoreCase))
            {
                suspiciousIndicators.Add($"Unusual issuer URI: {config.IssuerUri}");
            }

            // Check for localhost or internal IPs in issuer (common in AADInternals attacks)
            if (config.IssuerUri.Contains("localhost", StringComparison.OrdinalIgnoreCase) ||
                config.IssuerUri.Contains("127.0.0.1") ||
                config.IssuerUri.Contains("192.168.") ||
                config.IssuerUri.Contains("10."))
            {
                suspiciousIndicators.Add($"Internal/localhost issuer URI detected: {config.IssuerUri}");
            }
        }

        // Check signing certificate
        if (config.SigningCertificate != null)
        {
            // Very short certificate validity might indicate temporary backdoor
            var certExpiry = config.NextSigningCertificate; // Simplified check
            // Additional certificate analysis would go here
        }

        // Check for AADInternals-specific patterns
        if (!string.IsNullOrEmpty(config.DisplayName) && 
            config.DisplayName.Contains("AADInternals", StringComparison.OrdinalIgnoreCase))
        {
            suspiciousIndicators.Add("AADInternals signature detected in federation display name");
        }

        if (suspiciousIndicators.Count > 0)
        {
            return new BackdoorFinding
            {
                Type = BackdoorType.FederatedDomainBackdoor,
                Severity = SeverityLevel.Critical,
                Title = $"Suspicious federation configuration on domain: {domain.Id}",
                Description = $"The federated domain has suspicious characteristics that may indicate a backdoor installed via AADInternals or similar tools. Indicators: {string.Join("; ", suspiciousIndicators)}",
                AffectedResource = domain.Id,
                ResourceId = domain.Id,
                Details = new Dictionary<string, string>
                {
                    ["IssuerUri"] = config.IssuerUri ?? "N/A",
                    ["PassiveSignInUri"] = config.PassiveSignInUri ?? "N/A",
                    ["MetadataExchangeUri"] = config.MetadataExchangeUri ?? "N/A",
                    ["Indicators"] = string.Join(", ", suspiciousIndicators)
                },
                Recommendation = "Immediately investigate this federation. If not legitimate, convert the domain back to managed authentication using: Set-MsolDomainAuthentication -DomainName <domain> -Authentication Managed",
                MitreAttackTechnique = "T1484.002 - Domain Trust Modification"
            };
        }

        return null;
    }

    #endregion

    #region Service Principal Scanning

    /// <summary>
    /// Scan service principals for suspicious high-privilege permissions
    /// </summary>
    private async Task ScanServicePrincipalsAsync(BackdoorScanResult result, CancellationToken cancellationToken)
    {
        try
        {
            var servicePrincipals = await GraphClient.ServicePrincipals
                .GetAsync(r => r.QueryParameters.Top = 999, cancellationToken);

            if (servicePrincipals?.Value == null) return;

            result.ServicePrincipalsScanned = servicePrincipals.Value.Count;

            foreach (var sp in servicePrincipals.Value)
            {
                cancellationToken.ThrowIfCancellationRequested();

                // Skip known Microsoft first-party apps
                if (sp.AppId != null && KnownMicrosoftApps.FirstPartyAppIds.Contains(sp.AppId))
                    continue;

                var dangerousPerms = new List<string>();

                // Check app roles (application permissions)
                if (sp.AppRoles != null)
                {
                    foreach (var role in sp.AppRoles)
                    {
                        if (role.Value != null && KnownMicrosoftApps.DangerousPermissions.Contains(role.Value))
                        {
                            dangerousPerms.Add(role.Value);
                        }
                    }
                }

                // Check for suspicious characteristics
                var suspiciousIndicators = new List<string>();

                // Check for recently created apps with high privileges
                if (sp.CreatedDateTime.HasValue)
                {
                    var age = DateTime.UtcNow - sp.CreatedDateTime.Value;
                    if (age.TotalDays < 7 && dangerousPerms.Count > 0)
                    {
                        suspiciousIndicators.Add($"App created {age.TotalDays:F0} days ago with dangerous permissions");
                    }
                }

                // Check for apps without verified publisher
                if (string.IsNullOrEmpty(sp.PublisherName) && dangerousPerms.Count > 0)
                {
                    suspiciousIndicators.Add("No verified publisher");
                }

                // Check for suspicious app names
                if (sp.DisplayName != null)
                {
                    var suspiciousNames = new[] { "backdoor", "hack", "test", "temp", "aadinternals", "exploit" };
                    if (suspiciousNames.Any(n => sp.DisplayName.Contains(n, StringComparison.OrdinalIgnoreCase)))
                    {
                        suspiciousIndicators.Add($"Suspicious app name: {sp.DisplayName}");
                    }
                }

                if (dangerousPerms.Count > 0 || suspiciousIndicators.Count > 0)
                {
                    var severity = dangerousPerms.Count >= 3 ? SeverityLevel.Critical :
                                   dangerousPerms.Count >= 1 ? SeverityLevel.High :
                                   SeverityLevel.Medium;

                    result.Findings.Add(new BackdoorFinding
                    {
                        Type = BackdoorType.SuspiciousServicePrincipal,
                        Severity = severity,
                        Title = $"Suspicious service principal: {sp.DisplayName}",
                        Description = $"Service principal with potentially dangerous configuration detected. " +
                                     $"Dangerous permissions: {(dangerousPerms.Count > 0 ? string.Join(", ", dangerousPerms) : "None")}. " +
                                     $"Suspicious indicators: {(suspiciousIndicators.Count > 0 ? string.Join("; ", suspiciousIndicators) : "None")}",
                        AffectedResource = sp.DisplayName,
                        ResourceId = sp.Id,
                        Details = new Dictionary<string, string>
                        {
                            ["AppId"] = sp.AppId ?? "N/A",
                            ["ServicePrincipalId"] = sp.Id ?? "N/A",
                            ["Publisher"] = sp.PublisherName ?? "Unknown",
                            ["CreatedDateTime"] = sp.CreatedDateTime?.ToString("o") ?? "Unknown",
                            ["DangerousPermissions"] = string.Join(", ", dangerousPerms)
                        },
                        Recommendation = "Review this application's permissions and usage. If not recognized, consider deleting the service principal and app registration.",
                        MitreAttackTechnique = "T1098.001 - Account Manipulation: Additional Cloud Credentials"
                    });
                }
            }
        }
        catch (Exception ex)
        {
            result.Errors.Add($"Service principal scan error: {ex.Message}");
        }
    }

    #endregion

    #region OAuth Grant Scanning

    /// <summary>
    /// Scan OAuth2 permission grants for suspicious admin consent
    /// </summary>
    private async Task ScanOAuthGrantsAsync(BackdoorScanResult result, CancellationToken cancellationToken)
    {
        try
        {
            var grants = await GraphClient.Oauth2PermissionGrants
                .GetAsync(r => r.QueryParameters.Top = 999, cancellationToken);

            if (grants?.Value == null) return;

            result.OAuthGrantsScanned = grants.Value.Count;

            foreach (var grant in grants.Value)
            {
                cancellationToken.ThrowIfCancellationRequested();

                // Check for admin consent (AllPrincipals)
                if (grant.ConsentType == "AllPrincipals")
                {
                    var scopes = grant.Scope?.Split(' ', StringSplitOptions.RemoveEmptyEntries) ?? Array.Empty<string>();
                    var dangerousScopes = scopes.Where(s => KnownMicrosoftApps.DangerousPermissions.Contains(s)).ToList();

                    if (dangerousScopes.Count > 0)
                    {
                        // Get client app name
                        string? clientAppName = null;
                        try
                        {
                            var clientSp = await GraphClient.ServicePrincipals[grant.ClientId].GetAsync(cancellationToken: cancellationToken);
                            clientAppName = clientSp?.DisplayName;
                        }
                        catch { /* Ignore */ }

                        // Skip known Microsoft apps
                        if (clientAppName != null && KnownMicrosoftApps.FirstPartyAppIds.Contains(grant.ClientId ?? ""))
                            continue;

                        result.Findings.Add(new BackdoorFinding
                        {
                            Type = BackdoorType.AdminConsentGrant,
                            Severity = SeverityLevel.High,
                            Title = $"Admin consent grant with dangerous permissions: {clientAppName ?? grant.ClientId}",
                            Description = $"An application has been granted admin consent for dangerous permissions: {string.Join(", ", dangerousScopes)}. This could indicate an OAuth consent phishing attack or malicious app consent.",
                            AffectedResource = clientAppName ?? grant.ClientId,
                            ResourceId = grant.Id,
                            Details = new Dictionary<string, string>
                            {
                                ["ClientId"] = grant.ClientId ?? "N/A",
                                ["ResourceId"] = grant.ResourceId ?? "N/A",
                                ["AllScopes"] = grant.Scope ?? "N/A",
                                ["DangerousScopes"] = string.Join(", ", dangerousScopes)
                            },
                            Recommendation = "Review this consent grant immediately. If not legitimate, revoke the consent using: Remove-AzureADOAuth2PermissionGrant or delete from Enterprise Applications in Azure Portal.",
                            MitreAttackTechnique = "T1528 - Steal Application Access Token"
                        });
                    }
                }
            }
        }
        catch (Exception ex)
        {
            result.Errors.Add($"OAuth grant scan error: {ex.Message}");
        }
    }

    #endregion

    #region PTA Agent Scanning

    /// <summary>
    /// Scan for Pass-through Authentication agents (Backdoor #1 from Mandiant article)
    /// Note: This requires beta API and specific permissions
    /// </summary>
    private async Task ScanPTAAgentsAsync(BackdoorScanResult result, CancellationToken cancellationToken)
    {
        try
        {
            // PTA agents are accessed via the beta endpoint
            // We need to use a raw HTTP request since the SDK may not fully support this
            var httpClient = new HttpClient();
            var accessToken = await _authService.GetAccessTokenAsync();

            if (string.IsNullOrEmpty(accessToken))
            {
                result.Errors.Add("Could not obtain access token for PTA agent scan");
                return;
            }

            httpClient.DefaultRequestHeaders.Authorization = 
                new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", accessToken);

            // Try to get connectors (PTA agents appear as connectors)
            var response = await httpClient.GetAsync(
                "https://graph.microsoft.com/beta/onPremisesPublishingProfiles/provisioning/connectors",
                cancellationToken);

            if (response.IsSuccessStatusCode)
            {
                var content = await response.Content.ReadAsStringAsync(cancellationToken);
                var connectors = System.Text.Json.JsonSerializer.Deserialize<ConnectorResponse>(content);

                if (connectors?.Value != null)
                {
                    result.PTAAgentsScanned = connectors.Value.Count;

                    foreach (var connector in connectors.Value)
                    {
                        // Check for suspicious IPs (not in known internal IPs)
                        var isSuspicious = false;
                        var suspicionReasons = new List<string>();

                        if (!string.IsNullOrEmpty(connector.ExternalIp))
                        {
                            // Check if IP is not in known internal IPs
                            if (_knownInternalIps.Count > 0 && !_knownInternalIps.Contains(connector.ExternalIp))
                            {
                                isSuspicious = true;
                                suspicionReasons.Add($"External IP {connector.ExternalIp} not in known internal IP list");
                            }

                            // Check for known cloud provider IPs (potential attacker infrastructure)
                            if (IsCloudProviderIp(connector.ExternalIp))
                            {
                                isSuspicious = true;
                                suspicionReasons.Add($"IP {connector.ExternalIp} appears to be from a cloud provider");
                            }
                        }

                        // Check machine name for suspicious patterns
                        if (!string.IsNullOrEmpty(connector.MachineName))
                        {
                            var suspiciousMachinePatterns = new[] { "kali", "attack", "hack", "pentest", "c2", "beacon" };
                            if (suspiciousMachinePatterns.Any(p => connector.MachineName.Contains(p, StringComparison.OrdinalIgnoreCase)))
                            {
                                isSuspicious = true;
                                suspicionReasons.Add($"Suspicious machine name: {connector.MachineName}");
                            }
                        }

                        if (isSuspicious)
                        {
                            result.Findings.Add(new BackdoorFinding
                            {
                                Type = BackdoorType.UnknownPTAAgent,
                                Severity = SeverityLevel.Critical,
                                Title = $"Suspicious Pass-through Authentication Agent: {connector.MachineName}",
                                Description = $"A PTA agent was detected that may be malicious. This could indicate an attacker has installed AADInternals PTASpy on rogue infrastructure. Reasons: {string.Join("; ", suspicionReasons)}",
                                AffectedResource = connector.MachineName,
                                ResourceId = connector.Id,
                                Details = new Dictionary<string, string>
                                {
                                    ["ConnectorId"] = connector.Id ?? "N/A",
                                    ["MachineName"] = connector.MachineName ?? "Unknown",
                                    ["ExternalIp"] = connector.ExternalIp ?? "Unknown",
                                    ["Status"] = connector.Status ?? "Unknown"
                                },
                                Recommendation = "IMMEDIATE ACTION REQUIRED: Verify this PTA agent is legitimate. If not recognized, disable it immediately from Azure AD Connect settings and investigate for credential theft. Check C:\\PTASpy\\ on legitimate PTA servers for evidence of AADInternals.",
                                MitreAttackTechnique = "T1556.007 - Modify Authentication Process: Hybrid Identity"
                            });
                        }
                        else
                        {
                            // Log informational finding for all PTA agents for review
                            result.Findings.Add(new BackdoorFinding
                            {
                                Type = BackdoorType.PassThroughAuthenticationAgent,
                                Severity = SeverityLevel.Informational,
                                Title = $"PTA Agent detected: {connector.MachineName}",
                                Description = "A Pass-through Authentication agent was detected. Verify this agent is expected and running on legitimate infrastructure.",
                                AffectedResource = connector.MachineName,
                                ResourceId = connector.Id,
                                Details = new Dictionary<string, string>
                                {
                                    ["ConnectorId"] = connector.Id ?? "N/A",
                                    ["MachineName"] = connector.MachineName ?? "Unknown",
                                    ["ExternalIp"] = connector.ExternalIp ?? "Unknown",
                                    ["Status"] = connector.Status ?? "Unknown"
                                },
                                Recommendation = "Ensure this PTA agent is running on expected infrastructure and verify the external IP matches your organization's WAN IP.",
                                MitreAttackTechnique = "T1556.007 - Modify Authentication Process: Hybrid Identity"
                            });
                        }
                    }
                }
            }
            else if (response.StatusCode == System.Net.HttpStatusCode.Forbidden)
            {
                result.Errors.Add("Insufficient permissions to scan PTA agents. Requires Directory.ReadWrite.All permission.");
            }
            else
            {
                // PTA might not be enabled - this is not an error
                result.PTAAgentsScanned = 0;
            }
        }
        catch (Exception ex)
        {
            result.Errors.Add($"PTA agent scan error: {ex.Message}");
        }
    }

    /// <summary>
    /// Basic check for known cloud provider IP ranges
    /// </summary>
    private static bool IsCloudProviderIp(string ip)
    {
        // This is a simplified check - in production you'd use actual IP range databases
        // AWS, Azure, GCP, DigitalOcean, etc. IP ranges
        var cloudPatterns = new[]
        {
            "13.", "20.", "23.", "40.", "51.", "52.", // Azure
            "3.", "18.", "34.", "35.", "44.", "50.", "54.", // AWS
            "34.64.", "34.65.", "34.80.", "35.190.", "35.192.", // GCP
            "104.16.", "104.17.", "104.18.", "104.19.", // Cloudflare
            "159.65.", "159.89.", "167.99.", // DigitalOcean
        };

        return cloudPatterns.Any(p => ip.StartsWith(p));
    }

    private class ConnectorResponse
    {
        public List<ConnectorInfo>? Value { get; set; }
    }

    private class ConnectorInfo
    {
        public string? Id { get; set; }
        public string? MachineName { get; set; }
        public string? ExternalIp { get; set; }
        public string? Status { get; set; }
    }

    #endregion

    #region App Registration Scanning

    /// <summary>
    /// Scan app registrations for suspicious credentials
    /// </summary>
    private async Task ScanAppRegistrationsAsync(BackdoorScanResult result, CancellationToken cancellationToken)
    {
        try
        {
            var apps = await GraphClient.Applications
                .GetAsync(r => r.QueryParameters.Top = 999, cancellationToken);

            if (apps?.Value == null) return;

            foreach (var app in apps.Value)
            {
                cancellationToken.ThrowIfCancellationRequested();

                var suspiciousCredentials = new List<string>();

                // Check password credentials (secrets)
                if (app.PasswordCredentials != null)
                {
                    foreach (var cred in app.PasswordCredentials)
                    {
                        // Check for very long validity (potential persistence)
                        if (cred.EndDateTime.HasValue)
                        {
                            var validity = cred.EndDateTime.Value - DateTime.UtcNow;
                            if (validity.TotalDays > 730) // More than 2 years
                            {
                                suspiciousCredentials.Add($"Long-lived secret (expires in {validity.TotalDays:F0} days): {cred.DisplayName ?? cred.KeyId?.ToString()}");
                            }
                        }

                        // Check for recently added credentials
                        if (cred.StartDateTime.HasValue)
                        {
                            var age = DateTime.UtcNow - cred.StartDateTime.Value;
                            if (age.TotalDays < 7)
                            {
                                suspiciousCredentials.Add($"Recently added secret ({age.TotalDays:F0} days ago): {cred.DisplayName ?? cred.KeyId?.ToString()}");
                            }
                        }
                    }
                }

                // Check key credentials (certificates)
                if (app.KeyCredentials != null)
                {
                    foreach (var cred in app.KeyCredentials)
                    {
                        if (cred.StartDateTime.HasValue)
                        {
                            var age = DateTime.UtcNow - cred.StartDateTime.Value;
                            if (age.TotalDays < 7)
                            {
                                suspiciousCredentials.Add($"Recently added certificate ({age.TotalDays:F0} days ago): {cred.DisplayName ?? cred.KeyId?.ToString()}");
                            }
                        }
                    }
                }

                if (suspiciousCredentials.Count > 0)
                {
                    result.Findings.Add(new BackdoorFinding
                    {
                        Type = BackdoorType.SuspiciousCredential,
                        Severity = SeverityLevel.Medium,
                        Title = $"Suspicious credentials on app: {app.DisplayName}",
                        Description = $"The application has credentials that may warrant investigation: {string.Join("; ", suspiciousCredentials)}",
                        AffectedResource = app.DisplayName,
                        ResourceId = app.Id,
                        Details = new Dictionary<string, string>
                        {
                            ["AppId"] = app.AppId ?? "N/A",
                            ["ObjectId"] = app.Id ?? "N/A",
                            ["CredentialCount"] = ((app.PasswordCredentials?.Count ?? 0) + (app.KeyCredentials?.Count ?? 0)).ToString(),
                            ["SuspiciousCredentials"] = string.Join("; ", suspiciousCredentials)
                        },
                        Recommendation = "Review and rotate these credentials if they were not added by authorized personnel. Consider implementing credential expiration policies.",
                        MitreAttackTechnique = "T1098.001 - Account Manipulation: Additional Cloud Credentials"
                    });
                }
            }
        }
        catch (Exception ex)
        {
            result.Errors.Add($"App registration scan error: {ex.Message}");
        }
    }

    #endregion

    #region Federation Backdoor Revocation

    /// <summary>
    /// Revoke a federated domain backdoor by deleting the federation configuration
    /// This converts the domain back to managed authentication
    /// Requires Domain.ReadWrite.All permission
    /// </summary>
    /// <param name="domainId">The domain name (e.g., contoso.com)</param>
    /// <param name="federationConfigId">The federation configuration ID to delete</param>
    /// <returns>Result of the revocation operation</returns>
    public async Task<FederationRevocationResult> RevokeFederatedBackdoorAsync(
        string domainId, 
        string? federationConfigId = null,
        CancellationToken cancellationToken = default)
    {
        var result = new FederationRevocationResult
        {
            DomainId = domainId,
            FederationConfigId = federationConfigId
        };

        try
        {
            // If no config ID provided, get all federation configs for this domain
            if (string.IsNullOrEmpty(federationConfigId))
            {
                var configs = await GraphClient.Domains[domainId].FederationConfiguration
                    .GetAsync(cancellationToken: cancellationToken);

                if (configs?.Value == null || configs.Value.Count == 0)
                {
                    result.Success = false;
                    result.Message = $"No federation configuration found for domain {domainId}";
                    return result;
                }

                // Delete all federation configurations for this domain
                var deletedCount = 0;
                var errors = new List<string>();

                foreach (var config in configs.Value)
                {
                    if (config.Id == null) continue;

                    try
                    {
                        await GraphClient.Domains[domainId].FederationConfiguration[config.Id]
                            .DeleteAsync(cancellationToken: cancellationToken);
                        deletedCount++;
                    }
                    catch (Exception ex)
                    {
                        errors.Add($"Failed to delete config {config.Id}: {ex.Message}");
                    }
                }

                if (deletedCount > 0)
                {
                    result.Success = true;
                    result.ConvertedToManaged = true;
                    result.Message = $"Successfully deleted {deletedCount} federation configuration(s) for domain {domainId}. " +
                                    "The domain should now use managed authentication.";
                    
                    if (errors.Count > 0)
                    {
                        result.ErrorDetails = string.Join("; ", errors);
                    }
                }
                else
                {
                    result.Success = false;
                    result.Message = $"Failed to delete any federation configurations for domain {domainId}";
                    result.ErrorDetails = string.Join("; ", errors);
                }
            }
            else
            {
                // Delete specific federation configuration
                await GraphClient.Domains[domainId].FederationConfiguration[federationConfigId]
                    .DeleteAsync(cancellationToken: cancellationToken);

                result.Success = true;
                result.ConvertedToManaged = true;
                result.Message = $"Successfully deleted federation configuration {federationConfigId} for domain {domainId}. " +
                                "The domain should now use managed authentication.";
            }

            return result;
        }
        catch (ServiceException ex)
        {
            result.Success = false;
            result.Message = $"Failed to revoke federation backdoor: {ex.Message}";
            result.ErrorDetails = ex.ResponseStatusCode == 403 
                ? "Access denied. Ensure you have Domain.ReadWrite.All permission and are a Security Administrator or External Identity Provider Administrator."
                : ex.RawResponseBody;
            return result;
        }
        catch (Exception ex)
        {
            result.Success = false;
            result.Message = $"Error revoking federation backdoor: {ex.Message}";
            result.ErrorDetails = ex.ToString();
            return result;
        }
    }

    /// <summary>
    /// Mass revoke all detected federation backdoors
    /// </summary>
    /// <param name="findings">List of federation backdoor findings to revoke</param>
    /// <param name="progressCallback">Optional callback for progress updates</param>
    /// <returns>List of revocation results</returns>
    public async Task<List<FederationRevocationResult>> MassRevokeFederatedBackdoorsAsync(
        IEnumerable<BackdoorFinding> findings,
        Action<string, int, int>? progressCallback = null,
        CancellationToken cancellationToken = default)
    {
        var results = new List<FederationRevocationResult>();
        var federationFindings = findings
            .Where(f => f.Type == BackdoorType.FederatedDomainBackdoor)
            .ToList();

        if (federationFindings.Count == 0)
        {
            return results;
        }

        var processed = 0;
        foreach (var finding in federationFindings)
        {
            cancellationToken.ThrowIfCancellationRequested();

            processed++;
            progressCallback?.Invoke(finding.AffectedResource ?? finding.ResourceId ?? "Unknown", processed, federationFindings.Count);

            var domainId = finding.AffectedResource ?? finding.ResourceId;
            var federationConfigId = finding.Details.TryGetValue("FederationConfigId", out var configId) ? configId : null;

            if (string.IsNullOrEmpty(domainId))
            {
                results.Add(new FederationRevocationResult
                {
                    Success = false,
                    Message = "Domain ID not found in finding"
                });
                continue;
            }

            var result = await RevokeFederatedBackdoorAsync(domainId, federationConfigId, cancellationToken);
            results.Add(result);

            // Small delay to avoid rate limiting
            await Task.Delay(200, cancellationToken);
        }

        return results;
    }

    /// <summary>
    /// Check if a finding can be revoked (is a federation backdoor)
    /// </summary>
    public static bool CanRevokeFinding(BackdoorFinding finding)
    {
        return finding.Type == BackdoorType.FederatedDomainBackdoor;
    }

    #endregion

    #region Utility Methods

    /// <summary>
    /// Get all domains with their federation status
    /// </summary>
    public async Task<List<DomainInfo>> GetDomainsAsync(CancellationToken cancellationToken = default)
    {
        var result = new List<DomainInfo>();

        try
        {
            var domains = await GraphClient.Domains.GetAsync(cancellationToken: cancellationToken);

            if (domains?.Value == null) return result;

            foreach (var domain in domains.Value)
            {
                var info = new DomainInfo
                {
                    Id = domain.Id,
                    DomainName = domain.Id,
                    AuthenticationType = domain.AuthenticationType,
                    IsDefault = domain.IsDefault ?? false,
                    IsVerified = domain.IsVerified ?? false,
                    IsRoot = domain.IsRoot ?? false
                };

                if (string.Equals(domain.AuthenticationType, "Federated", StringComparison.OrdinalIgnoreCase))
                {
                    var config = await GetFederationConfigAsync(domain.Id!, cancellationToken);
                    if (config != null)
                    {
                        info.IssuerUri = config.IssuerUri;
                        info.PassiveSignInUri = config.PassiveSignInUri;
                        info.MetadataExchangeUri = config.MetadataExchangeUri;
                        info.FederationBrandName = config.DisplayName;
                    }
                }

                result.Add(info);
            }
        }
        catch
        {
            // Return empty list on error
        }

        return result;
    }

    #endregion
}
