using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Graph;
using Microsoft.Graph.Models;
using Safeguard.Models;

namespace Safeguard.Services;

/// <summary>
/// Service for detecting Azure AD/Entra ID backdoors
/// Based on:
/// - Mandiant: https://cloud.google.com/blog/topics/threat-intelligence/detecting-microsoft-365-azure-active-directory-backdoors
/// - AADInternals by Dr Nestori Syynimaa: https://aadinternals.com/talks/
/// </summary>
public class BackdoorDetectionService : IDisposable
{
    private readonly AuthenticationService _authService;
    private readonly List<string> _knownFederationIssuers = new();
    
    private readonly HttpClient _httpClient;
    private bool _disposed;
    
    private GraphServiceClient? _graphClient;
    
    private readonly SemaphoreSlim _httpClientLock = new(1, 1);

    public BackdoorDetectionService(AuthenticationService authService)
    {
        _authService = authService ?? throw new ArgumentNullException(nameof(authService));
        
        _httpClient = new HttpClient
        {
            Timeout = TimeSpan.FromSeconds(30) // Prevent indefinite hangs
        };
    }

    private GraphServiceClient GraphClient
    {
        get
        {
            _graphClient ??= _authService.GraphClient;
            return _graphClient ?? throw new InvalidOperationException("Not authenticated");
        }
    }


    /// <summary>
    /// Set known legitimate federation issuers
    /// </summary>
    public void SetKnownFederationIssuers(IEnumerable<string> issuers)
    {
        _knownFederationIssuers.Clear();
        foreach (var issuer in issuers)
        {
            var trimmedIssuer = issuer?.Trim();
            if (!string.IsNullOrEmpty(trimmedIssuer) && 
                Uri.TryCreate(trimmedIssuer, UriKind.Absolute, out var uri) &&
                (uri.Scheme == "https" || uri.Scheme == "http"))
            {
                _knownFederationIssuers.Add(trimmedIssuer);
            }
        }
    }

    private async Task<bool> ConfigureHttpClientAuthAsync(CancellationToken cancellationToken)
    {
        var accessToken = await _authService.GetAccessTokenAsync(cancellationToken);
        if (string.IsNullOrEmpty(accessToken))
        {
            return false;
        }
        
        await _httpClientLock.WaitAsync(cancellationToken);
        try
        {
            _httpClient.DefaultRequestHeaders.Authorization = 
                new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", accessToken);
            return true;
        }
        finally
        {
            _httpClientLock.Release();
        }
    }

    /// <summary>
    /// Run a comprehensive backdoor detection scan including AADInternals-specific checks
    /// </summary>
    public async Task<ExtendedBackdoorScanResult> RunFullScanAsync(
        Action<string>? progressCallback = null,
        CancellationToken cancellationToken = default)
    {
        var result = new ExtendedBackdoorScanResult
        {
            ScanStartTime = DateTime.UtcNow
        };

        try
        {
            // 1. Scan Entra Connect Sync configuration (AADInternals focus)
            progressCallback?.Invoke("Scanning Entra Connect Sync configuration...");
            await ScanEntraConnectSyncAsync(result, cancellationToken);

            // 2. Scan Cloud Sync agents (AADInternals focus)
            progressCallback?.Invoke("Scanning Cloud Sync agents...");
            await ScanCloudSyncAgentsAsync(result, cancellationToken);

            // 3. Scan domains for federation backdoors with enhanced checks
            progressCallback?.Invoke("Scanning domains for federation backdoors...");
            await ScanDomainsEnhancedAsync(result, cancellationToken);

            // 4. Scan for suspicious service principals
            progressCallback?.Invoke("Scanning service principals for high-privilege permissions...");
            await ScanServicePrincipalsAsync(result, cancellationToken);

            // 5. Scan OAuth2 permission grants
            progressCallback?.Invoke("Scanning OAuth2 permission grants...");
            await ScanOAuthGrantsAsync(result, cancellationToken);

            // 6. Scan for Pass-through Authentication agents
            progressCallback?.Invoke("Scanning for PTA agents...");
            await ScanPTAAgentsAsync(result, cancellationToken);

            // 7. Scan for suspicious app registrations with credentials
            progressCallback?.Invoke("Scanning app registrations for suspicious credentials...");
            await ScanAppRegistrationsAsync(result, cancellationToken);

            // 8. Scan sync service accounts (AADInternals focus)
            progressCallback?.Invoke("Scanning sync service accounts...");
            await ScanSyncServiceAccountsAsync(result, cancellationToken);

            progressCallback?.Invoke("Scanning for FOCI token abuse risks...");
            await ScanFociTokenAbuseAsync(result, cancellationToken);
            
            progressCallback?.Invoke("Scanning app redirect URIs for security issues...");
            await ScanRedirectUrisAsync(result, cancellationToken);
            
            progressCallback?.Invoke("Scanning for legacy implicit flow apps...");
            await ScanImplicitFlowAppsAsync(result, cancellationToken);
            
            progressCallback?.Invoke("Scanning Seamless SSO configuration...");
            await ScanSeamlessSsoAsync(result, cancellationToken);
            
            progressCallback?.Invoke("Scanning device registrations...");
            await ScanDeviceRegistrationsAsync(result, cancellationToken);

            // Added scan for Federated Identity Credentials
            progressCallback?.Invoke("Scanning Federated Identity Credentials...");
            await ScanFederatedIdentityCredentialsAsync(result, cancellationToken);

            // Added scan for Delegated Admin Relationships (GDAP/DAP)
            progressCallback?.Invoke("Scanning Delegated Admin Relationships (GDAP/DAP)...");
            await ScanDelegatedAdminRelationshipsAsync(result, cancellationToken);
            
            progressCallback?.Invoke("Scanning Cross-Tenant Access Policies...");
            await ScanCrossTenantAccessPoliciesAsync(result, cancellationToken);
            
            progressCallback?.Invoke("Scanning Guest Users with Admin Roles...");
            await ScanGuestUsersWithAdminRolesAsync(result, cancellationToken);

            // Calculate severity counts
            result.CriticalCount = result.Findings.Count(f => f.Severity == SeverityLevel.Critical);
            result.HighCount = result.Findings.Count(f => f.Severity == SeverityLevel.High);
            result.MediumCount = result.Findings.Count(f => f.Severity == SeverityLevel.Medium);
            result.LowCount = result.Findings.Count(f => f.Severity == SeverityLevel.Low);
            
            // Calculate hybrid-specific counts
            result.HybridIdentityIssues = result.Findings.Count(f => 
                f.Type is BackdoorType.EntraConnectSyncBackdoor or 
                          BackdoorType.EntraCloudSyncBackdoor or
                          BackdoorType.SoftMatchEnabled or
                          BackdoorType.HardMatchEnabled or
                          BackdoorType.PassThroughAuthenticationAgent or
                          BackdoorType.CloudSyncAgentBackdoor);
            
            result.FederationSecurityIssues = result.Findings.Count(f =>
                f.Type is BackdoorType.FederatedDomainBackdoor or
                          BackdoorType.FederationMfaBypass or
                          BackdoorType.FederationValidationDisabled or
                          BackdoorType.SecondarySigningCertificate or
                          BackdoorType.SuspiciousSigningCertificate);
            
            result.SyncConfigurationIssues = result.Findings.Count(f =>
                f.Type is BackdoorType.SyncServiceAccountCompromise or
                          BackdoorType.PrivilegedSyncAccount or
                          BackdoorType.DirectorySyncFeatureMisconfiguration);
        }
        catch (Exception)
        {
            result.Errors.Add("An error occurred during the scan. Please check connectivity and permissions.");
        }
        finally
        {
            result.ScanEndTime = DateTime.UtcNow;
        }

        return result;
    }

    /// <summary>
    /// Run a backdoor detection scan with configurable options
    /// </summary>
    public async Task<ExtendedBackdoorScanResult> ScanForBackdoorsAsync(
        BackdoorScanOptions options,
        Action<string>? progressCallback = null,
        CancellationToken cancellationToken = default)
    {
        var result = new ExtendedBackdoorScanResult
        {
            ScanStartTime = DateTime.UtcNow
        };

        try
        {
            // Run scans based on options
            if (options.ScanSyncConfiguration)
            {
                progressCallback?.Invoke("Scanning Entra Connect Sync configuration...");
                await ScanEntraConnectSyncAsync(result, cancellationToken);
                await ScanCloudSyncAgentsAsync(result, cancellationToken);
            }

            if (options.ScanFederatedDomains)
            {
                progressCallback?.Invoke("Scanning domains for federation backdoors...");
                await ScanDomainsEnhancedAsync(result, cancellationToken);
            }

            if (options.ScanServicePrincipals)
            {
                progressCallback?.Invoke("Scanning service principals...");
                await ScanServicePrincipalsAsync(result, cancellationToken);
            }

            if (options.ScanOAuthGrants)
            {
                progressCallback?.Invoke("Scanning OAuth2 permission grants...");
                await ScanOAuthGrantsAsync(result, cancellationToken);
            }

            if (options.ScanPTAAgents)
            {
                progressCallback?.Invoke("Scanning for PTA agents...");
                await ScanPTAAgentsAsync(result, cancellationToken);
            }

            if (options.ScanAppCredentials)
            {
                progressCallback?.Invoke("Scanning app registrations...");
                await ScanAppRegistrationsAsync(result, cancellationToken);
            }

            if (options.ScanFederatedIdentityCredentials)
            {
                progressCallback?.Invoke("Scanning federated identity credentials...");
                await ScanFederatedIdentityCredentialsAsync(result, cancellationToken);
            }

            if (options.ScanCrossTenantAccess)
            {
                progressCallback?.Invoke("Scanning cross-tenant access settings...");
                await ScanDelegatedAdminRelationshipsAsync(result, cancellationToken); // Renamed for consistency
                await ScanCrossTenantAccessPoliciesAsync(result, cancellationToken); // Renamed for consistency
            }

            if (options.ScanGuestAdmins)
            {
                progressCallback?.Invoke("Scanning for guest users with admin roles...");
                await ScanGuestUsersWithAdminRolesAsync(result, cancellationToken); // Renamed for consistency
            }

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

    #region Entra Connect Sync Scanning (AADInternals)

    /// <summary>
    /// Scan Entra Connect Sync configuration for backdoors
    /// Reference: AADInternals "The Ultimate Guide for Protecting Hybrid Identities"
    /// </summary>
    private async Task ScanEntraConnectSyncAsync(ExtendedBackdoorScanResult result, CancellationToken cancellationToken)
    {
        try
        {
            if (!await ConfigureHttpClientAuthAsync(cancellationToken))
            {
                result.Errors.Add("Could not obtain access token for sync configuration scan");
                return;
            }

            var response = await _httpClient.GetAsync(
                "https://graph.microsoft.com/beta/directory/onPremisesSynchronization",
                cancellationToken);

            if (response.IsSuccessStatusCode)
            {
                var content = await response.Content.ReadAsStringAsync(cancellationToken);
                var syncData = JsonDocument.Parse(content);
                
                var syncInfo = new EntraConnectSyncInfo();
                
                if (syncData.RootElement.TryGetProperty("value", out var valueArray) && 
                    valueArray.GetArrayLength() > 0)
                {
                    var syncConfig = valueArray[0];
                    
                    // Parse configuration
                    if (syncConfig.TryGetProperty("configuration", out var config))
                    {
                        // These aren't directly exposed but we check for sync being enabled
                    }
                    
                    // Parse features - critical for AADInternals backdoors
                    if (syncConfig.TryGetProperty("features", out var features))
                    {
                        syncInfo.SoftMatchEnabled = GetBoolProperty(features, "softMatchOnUpnEnabled");
                        syncInfo.HardMatchEnabled = !GetBoolProperty(features, "blockSoftMatchEnabled");
                        syncInfo.PasswordHashSyncEnabled = GetBoolProperty(features, "passwordSyncEnabled");
                        syncInfo.UnifiedGroupWritebackEnabled = GetBoolProperty(features, "unifiedGroupWritebackEnabled");
                        syncInfo.UserWritebackEnabled = GetBoolProperty(features, "userWritebackEnabled");
                        syncInfo.DeviceWritebackEnabled = GetBoolProperty(features, "deviceWritebackEnabled");
                        syncInfo.BlockCloudObjectTakeoverEnabled = GetBoolProperty(features, "blockCloudObjectTakeoverThroughHardMatchEnabled");
                        syncInfo.BlockSoftMatchEnabled = GetBoolProperty(features, "blockSoftMatchEnabled");
                        
                        // Check for dangerous sync feature configurations
                        // AADInternals: Soft/hard match allows account takeover
                        if (syncInfo.SoftMatchEnabled && !syncInfo.BlockSoftMatchEnabled)
                        {
                            result.Findings.Add(new BackdoorFinding
                            {
                                Type = BackdoorType.SoftMatchEnabled,
                                Severity = SeverityLevel.High,
                                Title = "Soft Match is enabled - allows account takeover",
                                Description = "Soft match (softMatchOnUpnEnabled) is enabled, which allows syncing on-premises objects to cloud objects " +
                                             "based on UPN or SMTP address. This can be exploited by attackers with access to Entra Connect to take over " +
                                             "cloud-only accounts by creating matching on-premises accounts.",
                                AffectedResource = "Directory Synchronization Configuration",
                                ResourceId = "SyncFeatures",
                                Details = new Dictionary<string, string>
                                {
                                    ["SoftMatchOnUpnEnabled"] = syncInfo.SoftMatchEnabled.ToString(),
                                    ["BlockSoftMatchEnabled"] = syncInfo.BlockSoftMatchEnabled.ToString()
                                },
                                Recommendation = "Disable soft match using: Set-MgBetaDirectoryOnPremiseSynchronization with blockSoftMatchEnabled = true. " +
                                                "Reference: AADInternals attack graph shows this enables account takeover.",
                                MitreAttackTechnique = "T1078.004 - Valid Accounts: Cloud Accounts"
                            });
                        }
                        
                        if (!syncInfo.BlockCloudObjectTakeoverEnabled)
                        {
                            result.Findings.Add(new BackdoorFinding
                            {
                                Type = BackdoorType.HardMatchEnabled,
                                Severity = SeverityLevel.High,
                                Title = "Cloud object takeover through hard match is not blocked",
                                Description = "Hard match takeover is not blocked (blockCloudObjectTakeoverThroughHardMatchEnabled = false). " +
                                             "This allows attackers with Entra Connect access to take over cloud objects by using matching ImmutableId/SourceAnchor.",
                                AffectedResource = "Directory Synchronization Configuration",
                                ResourceId = "SyncFeatures",
                                Details = new Dictionary<string, string>
                                {
                                    ["BlockCloudObjectTakeoverThroughHardMatchEnabled"] = syncInfo.BlockCloudObjectTakeoverEnabled.ToString()
                                },
                                Recommendation = "Enable cloud object takeover blocking: blockCloudObjectTakeoverThroughHardMatchEnabled to true. " +
                                                "This prevents attackers from hijacking cloud-only accounts via hard match.",
                                MitreAttackTechnique = "T1078.004 - Valid Accounts: Cloud Accounts"
                            });
                        }
                    }
                }
                
                result.SyncConfiguration = syncInfo;
            }
            else if (response.StatusCode == System.Net.HttpStatusCode.NotFound)
            {
                // No sync configured - this is fine
                result.SyncConfiguration = new EntraConnectSyncInfo { OnPremisesSyncEnabled = false };
            }
            else
            {
                result.Errors.Add("Could not retrieve sync configuration");
            }
        }
        catch (TaskCanceledException)
        {
            result.Errors.Add("Entra Connect Sync scan timed out");
        }
        catch (Exception)
        {
            result.Errors.Add("Entra Connect Sync scan encountered an error");
        }
    }

    private static bool GetBoolProperty(JsonElement element, string propertyName)
    {
        if (element.TryGetProperty(propertyName, out var prop) && prop.ValueKind == JsonValueKind.True)
            return true;
        return false;
    }

    private static string? GetStringProperty(JsonElement element, string propertyName)
    {
        if (element.TryGetProperty(propertyName, out var prop) && prop.ValueKind == JsonValueKind.String)
            return prop.GetString();
        return null;
    }

    #endregion

    #region Cloud Sync Agent Scanning (AADInternals)

    /// <summary>
    /// Scan Cloud Sync agents for backdoors
    /// Reference: AADInternals "Protecting Hybrid Identities" - Cloud Sync attack graph
    /// </summary>
    private async Task ScanCloudSyncAgentsAsync(ExtendedBackdoorScanResult result, CancellationToken cancellationToken)
    {
        try
        {
            if (!await ConfigureHttpClientAuthAsync(cancellationToken))
            {
                result.Errors.Add("Could not obtain access token for Cloud Sync scan");
                return;
            }

            var response = await _httpClient.GetAsync(
                "https://graph.microsoft.com/beta/onPremisesPublishingProfiles/provisioning/agents",
                cancellationToken);

            if (response.IsSuccessStatusCode)
            {
                var content = await response.Content.ReadAsStringAsync(cancellationToken);
                var agentsData = JsonDocument.Parse(content);

                if (agentsData.RootElement.TryGetProperty("value", out var agents))
                {
                    result.SyncAgentsScanned = agents.GetArrayLength();
                    
                    foreach (var agent in agents.EnumerateArray())
                    {
                        cancellationToken.ThrowIfCancellationRequested();
                        
                        var agentInfo = new CloudSyncAgentInfo
                        {
                            Id = GetStringProperty(agent, "id"),
                            MachineName = GetStringProperty(agent, "machineName"),
                            ExternalIp = GetStringProperty(agent, "externalIp"),
                            Status = GetStringProperty(agent, "status"),
                            Version = GetStringProperty(agent, "version")
                        };
                        
                        if (agent.TryGetProperty("createdDateTime", out var created) && 
                            DateTime.TryParse(created.GetString(), out var createdDate))
                        {
                            agentInfo.CreatedDateTime = createdDate;
                        }
                        
                        // Check for suspicious indicators
                        var suspiciousReasons = new List<string>();
                        
                        // Check IP against known internal IPs
                        // Removed check against _knownInternalIps
                        
                        // Check for recently created agents
                        if (agentInfo.CreatedDateTime.HasValue)
                        {
                            var age = DateTime.UtcNow - agentInfo.CreatedDateTime.Value;
                            if (age.TotalDays < 7)
                            {
                                suspiciousReasons.Add($"Agent created recently ({age.TotalDays:F0} days ago)");
                            }
                        }
                        
                        // Check for suspicious machine names
                        if (!string.IsNullOrEmpty(agentInfo.MachineName))
                        {
                            var suspiciousMachineNames = new[] { "test", "temp", "hack", "backdoor", "kali", "parrot" };
                            if (suspiciousMachineNames.Any(n => agentInfo.MachineName.Contains(n, StringComparison.OrdinalIgnoreCase)))
                            {
                                suspiciousReasons.Add("Suspicious machine name pattern");
                            }
                        }
                        
                        if (suspiciousReasons.Count > 0)
                        {
                            agentInfo.IsSuspicious = true;
                            agentInfo.SuspicionReasons = suspiciousReasons;
                            
                            result.Findings.Add(new BackdoorFinding
                            {
                                Type = BackdoorType.CloudSyncAgentBackdoor,
                                Severity = SeverityLevel.Critical,
                                Title = $"Suspicious Cloud Sync agent detected",
                                Description = $"A Cloud Sync agent with suspicious characteristics was detected. " +
                                             $"AADInternals can exploit Cloud Sync for persistent access. " +
                                             $"Indicators: {string.Join("; ", suspiciousReasons)}",
                                AffectedResource = agentInfo.MachineName ?? "Unknown",
                                ResourceId = agentInfo.Id,
                                Details = new Dictionary<string, string>
                                {
                                    ["AgentId"] = agentInfo.Id ?? "N/A",
                                    ["MachineName"] = agentInfo.MachineName ?? "N/A",
                                    ["ExternalIp"] = agentInfo.ExternalIp ?? "N/A",
                                    ["Status"] = agentInfo.Status ?? "N/A",
                                    ["CreatedDateTime"] = agentInfo.CreatedDateTime?.ToString("o") ?? "N/A",
                                    ["SuspicionReasons"] = string.Join(", ", suspiciousReasons)
                                },
                                Recommendation = "Contact Microsoft support to delete compromised Cloud Sync agent. " +
                                                "Disable or remove ADToAADSyncServiceAccount. Delete the Cloud Sync configuration from Azure Portal.",
                                MitreAttackTechnique = "T1556.007 - Modify Authentication Process: Hybrid Identity"
                            });
                        }
                        
                        result.SyncAgents.Add(agentInfo);
                    }
                }
            }
        }
        catch (TaskCanceledException)
        {
            result.Errors.Add("Cloud Sync agent scan timed out");
        }
        catch (Exception)
        {
            result.Errors.Add("Cloud Sync agent scan encountered an error");
        }
    }

    #endregion

    #region Enhanced Domain/Federation Scanning (AADInternals)

    /// <summary>
    /// Enhanced domain scanning with AADInternals-specific federation checks
    /// Reference: AADInternals federation backdoor attack graph
    /// </summary>
    private async Task ScanDomainsEnhancedAsync(ExtendedBackdoorScanResult result, CancellationToken cancellationToken)
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
                    var federationConfig = await GetFederationConfigAsync(domain.Id!, cancellationToken);

                    if (federationConfig != null)
                    {
                        // Enhanced federation analysis
                        var securityConfig = await AnalyzeFederationSecurityAsync(domain, federationConfig, cancellationToken);
                        result.FederationConfigs.Add(securityConfig);
                        result.FederationConfigsAnalyzed++;
                        
                        // Check for suspicious federation settings (existing)
                        var finding = AnalyzeFederatedDomain(domain, federationConfig);
                        if (finding != null)
                        {
                            finding.Details["FederationConfigId"] = federationConfig.Id ?? "";
                            result.Findings.Add(finding);
                        }
                        
                        // AADInternals-specific: Check federatedIdpMfaBehavior
                        // Should be "rejectMfaByFederatedIdp" to prevent MFA bypass
                        if (federationConfig.FederatedIdpMfaBehavior != "rejectMfaByFederatedIdp")
                        {
                            result.Findings.Add(new BackdoorFinding
                            {
                                Type = BackdoorType.FederationMfaBypass,
                                Severity = SeverityLevel.High,
                                Title = $"Federation MFA bypass possible on domain: {domain.Id}",
                                Description = "The federatedIdpMfaBehavior is not set to 'rejectMfaByFederatedIdp'. " +
                                             "This allows an attacker with access to the federation certificate to bypass Entra ID MFA " +
                                             "by claiming MFA was performed at the IdP level.",
                                AffectedResource = domain.Id,
                                ResourceId = domain.Id,
                                Details = new Dictionary<string, string>
                                {
                                    ["DomainId"] = domain.Id ?? "",
                                    ["CurrentFederatedIdpMfaBehavior"] = federationConfig.FederatedIdpMfaBehavior ?? "Not set",
                                    ["RecommendedValue"] = "rejectMfaByFederatedIdp"
                                },
                                Recommendation = "Set federatedIdpMfaBehavior to 'rejectMfaByFederatedIdp' to ensure Entra ID enforces MFA " +
                                                "even when the federated IdP claims MFA was performed. This prevents Golden SAML-style attacks.",
                                MitreAttackTechnique = "T1556.006 - Modify Authentication Process: Multi-Factor Authentication"
                            });
                        }
                        
                        // AADInternals-specific: Check for secondary signing certificate (stealthy persistence)
                        if (!string.IsNullOrEmpty(federationConfig.NextSigningCertificate))
                        {
                            result.Findings.Add(new BackdoorFinding
                            {
                                Type = BackdoorType.SecondarySigningCertificate,
                                Severity = SeverityLevel.Medium,
                                Title = $"Secondary signing certificate present on domain: {domain.Id}",
                                Description = "A secondary (next) signing certificate is configured. While this can be legitimate for certificate rollover, " +
                                             "attackers can add a secondary certificate for stealthy persistence. The secondary certificate is equally " +
                                             "accepted as a token signer but may be overlooked by security tools.",
                                AffectedResource = domain.Id,
                                ResourceId = domain.Id,
                                Details = new Dictionary<string, string>
                                {
                                    ["DomainId"] = domain.Id ?? "",
                                    ["HasSecondaryCert"] = "True"
                                },
                                Recommendation = "Verify the secondary signing certificate is legitimate and part of a planned certificate rollover. " +
                                                "If unexpected, remove it immediately and investigate potential compromise of AD FS.",
                                MitreAttackTechnique = "T1484.002 - Domain Trust Modification"
                            });
                        }
                        
                        // Check signing certificate for anomalies
                        if (!string.IsNullOrEmpty(federationConfig.SigningCertificate))
                        {
                            AnalyzeSigningCertificate(result, domain.Id!, federationConfig.SigningCertificate);
                        }
                    }
                    else
                    {
                        // Federated domain without accessible config
                        result.Findings.Add(new BackdoorFinding
                        {
                            Type = BackdoorType.FederatedDomainBackdoor,
                            Severity = SeverityLevel.High,
                            Title = $"Federated domain with inaccessible configuration: {domain.Id}",
                            Description = "A federated domain was found but its federation configuration could not be retrieved.",
                            AffectedResource = domain.Id,
                            ResourceId = domain.Id,
                            Recommendation = "Verify this domain's federation settings in the Azure Portal.",
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
            }
        }
        catch (TaskCanceledException)
        {
            result.Errors.Add("Domain scan timed out");
        }
        catch (Exception)
        {
            result.Errors.Add("Domain scan encountered an error");
        }
    }

    private async Task<FederationSecurityConfig> AnalyzeFederationSecurityAsync(
        Domain domain, 
        InternalDomainFederation config, 
        CancellationToken cancellationToken)
    {
        var securityConfig = new FederationSecurityConfig
        {
            DomainId = domain.Id,
            IssuerUri = config.IssuerUri,
            FederatedIdpMfaBehavior = config.FederatedIdpMfaBehavior,
            PromptLoginBehavior = config.PromptLoginBehavior,
            IsSignedAuthenticationRequestRequired = config.IsSignedAuthenticationRequestRequired ?? false,
            HasSecondarySigningCertificate = !string.IsNullOrEmpty(config.NextSigningCertificate)
        };

        // Parse signing certificate if available
        if (!string.IsNullOrEmpty(config.SigningCertificate))
        {
            try
            {
                var certBytes = Convert.FromBase64String(config.SigningCertificate);
                var cert = new System.Security.Cryptography.X509Certificates.X509Certificate2(certBytes);
                
                securityConfig.SigningCertificateThumbprint = cert.Thumbprint;
                securityConfig.SigningCertificateNotBefore = cert.NotBefore;
                securityConfig.SigningCertificateNotAfter = cert.NotAfter;
                securityConfig.SigningCertificateSubject = cert.Subject;
                securityConfig.SigningCertificateIssuer = cert.Issuer;
            }
            catch
            {
                securityConfig.SecurityIssues.Add("Could not parse signing certificate");
            }
        }

        // Check security issues
        if (config.FederatedIdpMfaBehavior != "rejectMfaByFederatedIdp")
            securityConfig.SecurityIssues.Add("MFA bypass possible - federatedIdpMfaBehavior not set correctly");
        
        if (!securityConfig.IsSignedAuthenticationRequestRequired)
            securityConfig.SecurityIssues.Add("Signed authentication requests not required");
        
        if (securityConfig.HasSecondarySigningCertificate)
            securityConfig.SecurityIssues.Add("Secondary signing certificate present");

        return securityConfig;
    }

    private void AnalyzeSigningCertificate(ExtendedBackdoorScanResult result, string domainId, string certBase64)
    {
        try
        {
            var certBytes = Convert.FromBase64String(certBase64);
            var cert = new System.Security.Cryptography.X509Certificates.X509Certificate2(certBytes);
            
            var suspiciousIndicators = new List<string>();
            
            // Check for self-signed certificate
            if (cert.Subject == cert.Issuer)
            {
                suspiciousIndicators.Add("Self-signed certificate");
            }
            
            // Check for very short validity period (might indicate temporary backdoor)
            var validityPeriod = cert.NotAfter - cert.NotBefore;
            if (validityPeriod.TotalDays < 30)
            {
                suspiciousIndicators.Add($"Very short validity period: {validityPeriod.TotalDays:F0} days");
            }
            
            // Check for very long validity period (unusual for enterprise)
            if (validityPeriod.TotalDays > 3650) // 10 years
            {
                suspiciousIndicators.Add($"Unusually long validity period: {validityPeriod.TotalDays / 365:F0} years");
            }
            
            // Check for suspicious subject names
            var suspiciousSubjectPatterns = new[] { "test", "temp", "backdoor", "aadinternals", "hack" };
            if (suspiciousSubjectPatterns.Any(p => cert.Subject.Contains(p, StringComparison.OrdinalIgnoreCase)))
            {
                suspiciousIndicators.Add($"Suspicious certificate subject: {cert.Subject}");
            }
            
            // Check if certificate was created very recently
            if (cert.NotBefore > DateTime.UtcNow.AddDays(-7))
            {
                suspiciousIndicators.Add($"Certificate created very recently: {cert.NotBefore:yyyy-MM-dd}");
            }
            
            if (suspiciousIndicators.Count > 0)
            {
                result.Findings.Add(new BackdoorFinding
                {
                    Type = BackdoorType.SuspiciousSigningCertificate,
                    Severity = SeverityLevel.High,
                    Title = $"Suspicious token signing certificate on domain: {domainId}",
                    Description = $"The federation token signing certificate has suspicious characteristics: {string.Join("; ", suspiciousIndicators)}. " +
                                 "This may indicate an AD FS compromise or backdoor installation via AADInternals.",
                    AffectedResource = domainId,
                    ResourceId = domainId,
                    Details = new Dictionary<string, string>
                    {
                        ["DomainId"] = domainId,
                        ["CertSubject"] = cert.Subject,
                        ["CertIssuer"] = cert.Issuer,
                        ["CertThumbprint"] = cert.Thumbprint,
                        ["ValidFrom"] = cert.NotBefore.ToString("o"),
                        ["ValidTo"] = cert.NotAfter.ToString("o"),
                        ["SuspiciousIndicators"] = string.Join(", ", suspiciousIndicators)
                    },
                    Recommendation = "Verify the certificate is legitimate. If AD FS was compromised, rotate the token signing certificate " +
                                    "and consider rebuilding the AD FS farm. Store certificates in TPM or HSM.",
                    MitreAttackTechnique = "T1552.004 - Unsecured Credentials: Private Keys"
                });
            }
        }
        catch
        {
            // Certificate parsing failed - already logged elsewhere
        }
    }

    #endregion

    #region Sync Service Account Scanning (AADInternals)

    /// <summary>
    /// Scan sync service accounts for suspicious configurations
    /// Reference: AADInternals Entra Connect Sync attack graph
    /// </summary>
    private async Task ScanSyncServiceAccountsAsync(ExtendedBackdoorScanResult result, CancellationToken cancellationToken)
    {
        try
        {
            // Search for sync service accounts
            var users = await GraphClient.Users
                .GetAsync(r => 
                {
                    r.QueryParameters.Top = 999;
                    r.QueryParameters.Filter = "startsWith(displayName, 'Sync_') or startsWith(displayName, 'MSOL_') or startsWith(displayName, 'AAD_')";
                }, cancellationToken);

            if (users?.Value == null) return;

            foreach (var user in users.Value)
            {
                cancellationToken.ThrowIfCancellationRequested();
                
                // Check if this is a sync service account
                var isSyncAccount = KnownMicrosoftApps.SyncServiceAccountPatterns
                    .Any(p => user.DisplayName?.StartsWith(p, StringComparison.OrdinalIgnoreCase) == true ||
                              user.UserPrincipalName?.Contains(p, StringComparison.OrdinalIgnoreCase) == true);
                
                if (!isSyncAccount) continue;
                
                // Get directory roles for this account
                var memberOf = await GraphClient.Users[user.Id].MemberOf.GetAsync(cancellationToken: cancellationToken);
                var roles = memberOf?.Value?
                    .OfType<DirectoryRole>()
                    .Select(r => r.DisplayName)
                    .ToList() ?? new List<string?>();
                
                var dangerousRoles = roles
                    .Where(r => r != null && KnownMicrosoftApps.DangerousSyncRoles.Contains(r))
                    .ToList();
                
                // Sync accounts should only have "Directory Synchronization Accounts" role
                if (dangerousRoles.Any(r => r != "Directory Synchronization Accounts"))
                {
                    result.Findings.Add(new BackdoorFinding
                    {
                        Type = BackdoorType.PrivilegedSyncAccount,
                        Severity = SeverityLevel.Critical,
                        Title = $"Sync service account with excessive privileges: {user.DisplayName}",
                        Description = $"The sync service account has dangerous roles beyond 'Directory Synchronization Accounts': " +
                                     $"{string.Join(", ", dangerousRoles)}. This could indicate privilege escalation or account abuse " +
                                     "following an Entra Connect compromise.",
                        AffectedResource = user.DisplayName,
                        ResourceId = user.Id,
                        Details = new Dictionary<string, string>
                        {
                            ["UserId"] = user.Id ?? "N/A",
                            ["UserPrincipalName"] = user.UserPrincipalName ?? "N/A",
                            ["DisplayName"] = user.DisplayName ?? "N/A",
                            ["DangerousRoles"] = string.Join(", ", dangerousRoles),
                            ["AllRoles"] = string.Join(", ", roles.Where(r => r != null))
                        },
                        Recommendation = "Remove excessive roles from the sync service account. Sync accounts should only have " +
                                        "'Directory Synchronization Accounts' role. Investigate how additional roles were assigned.",
                        MitreAttackTechnique = "T1078.004 - Valid Accounts: Cloud Accounts"
                    });
                }
                
                // Check for multiple sync accounts (should typically be one per Entra Connect server)
                if (result.SyncConfiguration != null)
                {
                    result.SyncConfiguration.SyncServiceAccountName = user.DisplayName;
                    result.SyncConfiguration.SyncServiceAccountType = "User";
                    result.SyncConfiguration.SyncServiceAccountRoles = roles.Where(r => r != null).Cast<string>().ToList();
                }
            }
            
            // Also check for ADToAADSyncServiceAccount (Cloud Sync)
            var cloudSyncAccounts = await GraphClient.Users
                .GetAsync(r =>
                {
                    r.QueryParameters.Top = 100;
                    r.QueryParameters.Filter = "displayName eq 'On-Premises Directory Synchronization Service Account'";
                }, cancellationToken);

            if (cloudSyncAccounts?.Value != null && cloudSyncAccounts.Value.Count > 1)
            {
                result.Findings.Add(new BackdoorFinding
                {
                    Type = BackdoorType.SyncServiceAccountCompromise,
                    Severity = SeverityLevel.Medium,
                    Title = "Multiple Cloud Sync service accounts detected",
                    Description = $"Found {cloudSyncAccounts.Value.Count} Cloud Sync service accounts. There should typically be only one. " +
                                 "Additional accounts may indicate a compromise or rogue Cloud Sync installation.",
                    AffectedResource = "Cloud Sync Service Accounts",
                    ResourceId = "ADToAADSyncServiceAccount",
                    Details = new Dictionary<string, string>
                    {
                        ["AccountCount"] = cloudSyncAccounts.Value.Count.ToString()
                    },
                    Recommendation = "Review all Cloud Sync service accounts and remove any that are not legitimate. " +
                                    "Contact Microsoft support to delete compromised agent registrations.",
                    MitreAttackTechnique = "T1136.003 - Create Account: Cloud Account"
                });
            }
        }
        catch (TaskCanceledException)
        {
            result.Errors.Add("Sync service account scan timed out");
        }
        catch (Exception)
        {
            result.Errors.Add("Sync service account scan encountered an error");
        }
    }

    #endregion

    #region Existing scanning methods (Domain, Service Principal, OAuth, PTA, App Registration)

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

        if (!string.IsNullOrEmpty(config.IssuerUri))
        {
            // Check for suspicious issuer URI patterns from AADInternals
            foreach (var pattern in KnownMicrosoftApps.SuspiciousIssuerPatterns)
            {
                if (config.IssuerUri.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                {
                    suspiciousIndicators.Add($"Suspicious issuer URI pattern '{pattern}': {config.IssuerUri}");
                    break;
                }
            }
            
            // Check if issuer is not in known legitimate issuers
            if (_knownFederationIssuers.Count > 0 && 
                !_knownFederationIssuers.Any(i => config.IssuerUri.Contains(i, StringComparison.OrdinalIgnoreCase)))
            {
                suspiciousIndicators.Add($"Unknown issuer not in whitelist: {config.IssuerUri}");
            }
        }

        // Check for AADInternals signature
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
                Description = $"The federated domain has suspicious characteristics indicating potential AADInternals backdoor. " +
                             $"Indicators: {string.Join("; ", suspiciousIndicators)}",
                AffectedResource = domain.Id,
                ResourceId = domain.Id,
                Details = new Dictionary<string, string>
                {
                    ["IssuerUri"] = config.IssuerUri ?? "N/A",
                    ["PassiveSignInUri"] = config.PassiveSignInUri ?? "N/A",
                    ["MetadataExchangeUri"] = config.MetadataExchangeUri ?? "N/A",
                    ["Indicators"] = string.Join(", ", suspiciousIndicators)
                },
                Recommendation = "Immediately investigate this federation. Convert the domain back to managed authentication " +
                                "and rotate all AD FS certificates if compromise is confirmed.",
                MitreAttackTechnique = "T1484.002 - Domain Trust Modification"
            };
        }

        return null;
    }

    #region Service Principal Scanning

    private async Task ScanServicePrincipalsAsync(ExtendedBackdoorScanResult result, CancellationToken cancellationToken)
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

                if (sp.AppId != null && KnownMicrosoftApps.FirstPartyAppIds.Contains(sp.AppId))
                    continue;

                var dangerousPerms = new List<string>();

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

                var suspiciousIndicators = new List<string>();

                if (sp.CreatedDateTime.HasValue)
                {
                    var age = DateTime.UtcNow - sp.CreatedDateTime.Value;
                    if (age.TotalDays < 7 && dangerousPerms.Count > 0)
                    {
                        suspiciousIndicators.Add($"App created {age.TotalDays:F0} days ago with dangerous permissions");
                    }
                }

                if (string.IsNullOrEmpty(sp.PublisherName) && dangerousPerms.Count > 0)
                {
                    suspiciousIndicators.Add("No verified publisher");
                }

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
                        Description = $"Service principal with potentially dangerous configuration. " +
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
                        Recommendation = "Review this application's permissions. If not recognized, delete the service principal.",
                        MitreAttackTechnique = "T1098.001 - Account Manipulation: Additional Cloud Credentials"
                    });
                }
            }
        }
        catch (TaskCanceledException)
        {
            result.Errors.Add("Service principal scan timed out");
        }
        catch (Exception)
        {
            result.Errors.Add("Service principal scan encountered an error");
        }
    }

    #endregion

    #region OAuth Grant Scanning

    private async Task ScanOAuthGrantsAsync(ExtendedBackdoorScanResult result, CancellationToken cancellationToken)
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

                if (grant.ConsentType == "AllPrincipals")
                {
                    var scopes = grant.Scope?.Split(' ', StringSplitOptions.RemoveEmptyEntries) ?? Array.Empty<string>();
                    var dangerousScopes = scopes.Where(s => KnownMicrosoftApps.DangerousPermissions.Contains(s)).ToList();

                    if (dangerousScopes.Count > 0)
                    {
                        string? clientAppName = null;
                        try
                        {
                            var clientSp = await GraphClient.ServicePrincipals[grant.ClientId].GetAsync(cancellationToken: cancellationToken);
                            clientAppName = clientSp?.DisplayName;
                        }
                        catch { }

                        if (clientAppName != null && KnownMicrosoftApps.FirstPartyAppIds.Contains(grant.ClientId ?? ""))
                            continue;

                        result.Findings.Add(new BackdoorFinding
                        {
                            Type = BackdoorType.AdminConsentGrant,
                            Severity = SeverityLevel.High,
                            Title = $"Admin consent grant with dangerous permissions: {clientAppName ?? grant.ClientId}",
                            Description = $"Application granted admin consent for dangerous permissions: {string.Join(", ", dangerousScopes)}.",
                            AffectedResource = clientAppName ?? grant.ClientId,
                            ResourceId = grant.Id,
                            Details = new Dictionary<string, string>
                            {
                                ["ClientId"] = grant.ClientId ?? "N/A",
                                ["ResourceId"] = grant.ResourceId ?? "N/A",
                                ["AllScopes"] = grant.Scope ?? "N/A",
                                ["DangerousScopes"] = string.Join(", ", dangerousScopes)
                            },
                            Recommendation = "Review this consent grant. If not legitimate, revoke it immediately.",
                            MitreAttackTechnique = "T1528 - Steal Application Access Token"
                        });
                    }
                }
            }
        }
        catch (TaskCanceledException)
        {
            result.Errors.Add("OAuth grant scan timed out");
        }
        catch (Exception)
        {
            result.Errors.Add("OAuth grant scan encountered an error");
        }
    }

    #endregion

    #region PTA Agent Scanning

    private async Task ScanPTAAgentsAsync(ExtendedBackdoorScanResult result, CancellationToken cancellationToken)
    {
        try
        {
            if (!await ConfigureHttpClientAuthAsync(cancellationToken)) return;

            // Get PTA agents via beta API
            var response = await _httpClient.GetAsync(
                "https://graph.microsoft.com/beta/onPremisesPublishingProfiles/provisioning/publishedResources?$expand=agentGroups($expand=agents)",
                cancellationToken);

            if (!response.IsSuccessStatusCode) return;

            var content = await response.Content.ReadAsStringAsync(cancellationToken);
            var data = JsonDocument.Parse(content);

            if (!data.RootElement.TryGetProperty("value", out var resources)) return;

            foreach (var resource in resources.EnumerateArray())
            {
                if (!resource.TryGetProperty("agentGroups", out var groups)) continue;

                foreach (var group in groups.EnumerateArray())
                {
                    if (!group.TryGetProperty("agents", out var agents)) continue;

                    result.PTAAgentsScanned += agents.GetArrayLength();

                    foreach (var agent in agents.EnumerateArray())
                    {
                        var machineName = GetStringProperty(agent, "machineName");
                        var externalIp = GetStringProperty(agent, "externalIp");
                        var status = GetStringProperty(agent, "status");
                        var agentId = GetStringProperty(agent, "id");
                        
                        DateTimeOffset? createdDateTime = null;
                        if (agent.TryGetProperty("createdDateTime", out var createdProp) && 
                            createdProp.ValueKind == JsonValueKind.String)
                        {
                            DateTimeOffset.TryParse(createdProp.GetString(), out var parsed);
                            createdDateTime = parsed;
                        }

                        var isRecentlyCreated = createdDateTime.HasValue && 
                                               createdDateTime.Value > DateTimeOffset.UtcNow.AddDays(-7);
                        
                        var severity = isRecentlyCreated ? SeverityLevel.Critical : SeverityLevel.Medium;
                        var title = isRecentlyCreated 
                            ? $"Recently created PTA agent: {machineName}" 
                            : $"PTA agent for review: {machineName}";
                        var description = isRecentlyCreated
                            ? $"PTA agent created within the last 7 days. This requires immediate verification as it could indicate PTASpy or similar attack."
                            : $"PTA agent detected. Verify this agent is legitimate and authorized for your environment.";

                        result.Findings.Add(new BackdoorFinding
                        {
                            Type = BackdoorType.PassThroughAuthenticationAgent,
                            Severity = severity,
                            Title = title,
                            Description = description,
                            AffectedResource = machineName,
                            ResourceId = agentId,
                            Details = new Dictionary<string, string>
                            {
                                ["AgentId"] = agentId ?? "N/A",
                                ["MachineName"] = machineName ?? "N/A",
                                ["ExternalIp"] = externalIp ?? "N/A",
                                ["Status"] = status ?? "N/A",
                                ["CreatedDateTime"] = createdDateTime?.ToString("yyyy-MM-dd HH:mm:ss UTC") ?? "Unknown",
                                ["RecentlyCreated"] = isRecentlyCreated ? "YES - REQUIRES VERIFICATION" : "No"
                            },
                            Recommendation = isRecentlyCreated
                                ? "URGENT: Verify this agent was legitimately deployed. If not, contact Microsoft support to delete it immediately."
                                : "Verify this agent is authorized. Document machine name and IP for your records.",
                            MitreAttackTechnique = "T1556.007 - Modify Authentication Process: Hybrid Identity"
                        });
                    }
                }
            }
        }
        catch (TaskCanceledException)
        {
            result.Errors.Add("PTA agent scan timed out");
        }
        catch (Exception)
        {
            result.Errors.Add("PTA agent scan encountered an error");
        }
    }

    #endregion

    #region App Registration Scanning

    private async Task ScanAppRegistrationsAsync(ExtendedBackdoorScanResult result, CancellationToken cancellationToken)
    {
        try
        {
            var apps = await GraphClient.Applications
                .GetAsync(r =>
                {
                    r.QueryParameters.Top = 999;
                    r.QueryParameters.Select = new[] { "id", "appId", "displayName", "createdDateTime", "passwordCredentials", "keyCredentials" };
                }, cancellationToken);

            if (apps?.Value == null) return;

            foreach (var app in apps.Value)
            {
                cancellationToken.ThrowIfCancellationRequested();

                var recentCreds = new List<string>();

                if (app.PasswordCredentials != null)
                {
                    foreach (var cred in app.PasswordCredentials)
                    {
                        if (cred.StartDateTime.HasValue &&
                            cred.StartDateTime.Value > DateTime.UtcNow.AddDays(-7))
                        {
                            recentCreds.Add($"Password credential added {(DateTime.UtcNow - cred.StartDateTime.Value).TotalDays:F0} days ago");
                        }
                    }
                }

                if (app.KeyCredentials != null)
                {
                    foreach (var cred in app.KeyCredentials)
                    {
                        if (cred.StartDateTime.HasValue &&
                            cred.StartDateTime.Value > DateTime.UtcNow.AddDays(-7))
                        {
                            recentCreds.Add($"Key credential added {(DateTime.UtcNow - cred.StartDateTime.Value).TotalDays:F0} days ago");
                        }
                    }
                }

                if (recentCreds.Count > 0)
                {
                    result.Findings.Add(new BackdoorFinding
                    {
                        Type = BackdoorType.SuspiciousCredential,
                        Severity = SeverityLevel.Medium,
                        Title = $"Recently added credentials on app: {app.DisplayName}",
                        Description = $"The application has credentials added in the last 7 days: {string.Join("; ", recentCreds)}",
                        AffectedResource = app.DisplayName,
                        ResourceId = app.Id,
                        Details = new Dictionary<string, string>
                        {
                            ["AppId"] = app.AppId ?? "N/A",
                            ["ApplicationId"] = app.Id ?? "N/A",
                            ["RecentCredentials"] = string.Join(", ", recentCreds)
                        },
                        Recommendation = "Verify these credentials were added legitimately. If not, remove them and investigate.",
                        MitreAttackTechnique = "T1098.001 - Account Manipulation: Additional Cloud Credentials"
                    });
                }
            }
        }
        catch (TaskCanceledException)
        {
            result.Errors.Add("App registration scan timed out");
        }
        catch (Exception)
        {
            result.Errors.Add("App registration scan encountered an error");
        }
    }

    #endregion

    #region Token-Based Attack Detection (Tokens Everywhere)

    /// <summary>
    /// Scan for FOCI (Family of Client IDs) token abuse risks
    /// FOCI apps share refresh tokens, so a stolen token can access multiple services
    /// </summary>
    private async Task ScanFociTokenAbuseAsync(ExtendedBackdoorScanResult result, CancellationToken cancellationToken)
    {
        try
        {
            // Get OAuth grants that involve FOCI apps with dangerous scopes
            var grants = await _graphClient.Oauth2PermissionGrants
                .GetAsync(r => r.QueryParameters.Filter = "consentType eq 'AllPrincipals'", cancellationToken);

            if (grants?.Value == null) return;

            foreach (var grant in grants.Value)
            {
                if (string.IsNullOrEmpty(grant.ClientId)) continue;
                
                // Check if this is a FOCI app
                var sp = await _graphClient.ServicePrincipals[grant.ClientId]
                    .GetAsync(r => r.QueryParameters.Select = new[] { "appId", "displayName" }, cancellationToken);
                
                if (sp?.AppId != null && FociClientIds.FociApps.ContainsKey(sp.AppId))
                {
                    // Check if dangerous scopes are granted
                    var grantedScopes = grant.Scope?.Split(' ', StringSplitOptions.RemoveEmptyEntries) ?? Array.Empty<string>();
                    var dangerousScopes = grantedScopes
                        .Where(s => FociClientIds.HighRiskFociScopes.Contains(s))
                        .ToList();

                    if (dangerousScopes.Any() && grantedScopes.Contains("offline_access"))
                    {
                        result.Findings.Add(new BackdoorFinding
                        {
                            Type = BackdoorType.FociTokenAbuse,
                            Severity = SeverityLevel.High,
                            Title = $"FOCI App with Dangerous Scopes: {sp.DisplayName}",
                            Description = $"This FOCI family app has admin consent for dangerous scopes including offline_access. " +
                                          $"A stolen refresh token can be exchanged across all FOCI apps, expanding attack surface.",
                            AffectedResource = sp.DisplayName,
                            ResourceId = sp.AppId,
                            Details = new Dictionary<string, string>
                            {
                                { "AppId", sp.AppId },
                                { "FociFamily", FociClientIds.FociApps[sp.AppId] },
                                { "DangerousScopes", string.Join(", ", dangerousScopes) },
                                { "AllScopes", grant.Scope ?? "" }
                            },
                            Recommendation = "Review if admin consent is necessary. Consider removing offline_access or sensitive scopes. " +
                                             "Monitor for token theft via sign-in logs.",
                            MitreAttackTechnique = "T1528 - Steal Application Access Token"
                        });
                    }
                }
            }
        }
        catch (Exception)
        {
            result.Errors.Add("Failed to scan for FOCI token abuse risks.");
        }
    }

    /// <summary>
    /// Scan for apps with dangerous redirect URIs that could be used for token theft
    /// </summary>
    private async Task ScanRedirectUrisAsync(ExtendedBackdoorScanResult result, CancellationToken cancellationToken)
    {
        try
        {
            var apps = await _graphClient.Applications
                .GetAsync(r => r.QueryParameters.Select = new[] 
                { 
                    "id", "appId", "displayName", "web", "spa", "publicClient" 
                }, cancellationToken);

            if (apps?.Value == null) return;

            foreach (var app in apps.Value)
            {
                var suspiciousUris = new List<string>();
                var allUris = new List<string>();
                
                // Collect all redirect URIs
                if (app.Web?.RedirectUris != null)
                    allUris.AddRange(app.Web.RedirectUris);
                if (app.Spa?.RedirectUris != null)
                    allUris.AddRange(app.Spa.RedirectUris);
                if (app.PublicClient?.RedirectUris != null)
                    allUris.AddRange(app.PublicClient.RedirectUris);

                // Check each URI against dangerous patterns
                foreach (var uri in allUris)
                {
                    var lowerUri = uri.ToLowerInvariant();
                    foreach (var pattern in SuspiciousRedirectPatterns.DangerousPatterns)
                    {
                        if (lowerUri.Contains(pattern.ToLowerInvariant()))
                        {
                            suspiciousUris.Add(uri);
                            break;
                        }
                    }
                }

                if (suspiciousUris.Any())
                {
                    var severity = suspiciousUris.Any(u => 
                        u.Contains("javascript:", StringComparison.OrdinalIgnoreCase) ||
                        u.Contains("data:", StringComparison.OrdinalIgnoreCase))
                        ? SeverityLevel.Critical
                        : SeverityLevel.High;

                    result.Findings.Add(new BackdoorFinding
                    {
                        Type = BackdoorType.SuspiciousRedirectUri,
                        Severity = severity,
                        Title = $"Suspicious Redirect URI: {app.DisplayName}",
                        Description = $"This application has redirect URIs that could be exploited for token theft. " +
                                      $"Attackers could intercept OAuth tokens through these endpoints.",
                        AffectedResource = app.DisplayName,
                        ResourceId = app.AppId,
                        Details = new Dictionary<string, string>
                        {
                            { "AppId", app.AppId ?? "" },
                            { "SuspiciousUris", string.Join("; ", suspiciousUris) },
                            { "TotalRedirectUris", allUris.Count.ToString() }
                        },
                        Recommendation = "Remove or replace suspicious redirect URIs with secure HTTPS endpoints. " +
                                         "Avoid localhost, HTTP, and tunneling services in production.",
                        MitreAttackTechnique = "T1528 - Steal Application Access Token"
                    });
                }
            }
        }
        catch (Exception)
        {
            result.Errors.Add("Failed to scan redirect URIs.");
        }
    }

    /// <summary>
    /// Scan for apps using legacy implicit flow (tokens in URL fragment)
    /// </summary>
    private async Task ScanImplicitFlowAppsAsync(ExtendedBackdoorScanResult result, CancellationToken cancellationToken)
    {
        try
        {
            var apps = await _graphClient.Applications
                .GetAsync(r => r.QueryParameters.Select = new[] 
                { 
                    "id", "appId", "displayName", "web", "isFallbackPublicClient" 
                }, cancellationToken);

            if (apps?.Value == null) return;

            foreach (var app in apps.Value)
            {
                var issues = new List<string>();
                
                // Check for implicit flow
                if (app.Web?.ImplicitGrantSettings?.EnableAccessTokenIssuance == true)
                {
                    issues.Add("Access token in URL fragment enabled");
                }
                if (app.Web?.ImplicitGrantSettings?.EnableIdTokenIssuance == true)
                {
                    issues.Add("ID token in URL fragment enabled");
                }
                
                // Check for public client with secrets (misconfiguration)
                if (app.IsFallbackPublicClient == true)
                {
                    // Public clients shouldn't have secrets - check separately
                    issues.Add("Configured as public client (fallback)");
                }

                if (issues.Any(i => i.Contains("URL fragment")))
                {
                    result.Findings.Add(new BackdoorFinding
                    {
                        Type = BackdoorType.ImplicitFlowEnabled,
                        Severity = SeverityLevel.Medium,
                        Title = $"Implicit Flow Enabled: {app.DisplayName}",
                        Description = $"This application uses the legacy OAuth implicit flow which exposes tokens in URL fragments. " +
                                      $"Tokens can be leaked via browser history, referrer headers, and logging.",
                        AffectedResource = app.DisplayName,
                        ResourceId = app.AppId,
                        Details = new Dictionary<string, string>
                        {
                            { "AppId", app.AppId ?? "" },
                            { "Issues", string.Join("; ", issues) }
                        },
                        Recommendation = "Migrate to authorization code flow with PKCE. " +
                                         "Disable implicit grant in app registration settings.",
                        MitreAttackTechnique = "T1528 - Steal Application Access Token"
                    });
                }
            }
        }
        catch (Exception)
        {
            result.Errors.Add("Failed to scan for implicit flow apps.");
        }
    }

    /// <summary>
    /// Scan for Seamless SSO configuration issues (AZUREADSSOACC backdoor)
    /// </summary>
    private async Task ScanSeamlessSsoAsync(ExtendedBackdoorScanResult result, CancellationToken cancellationToken)
    {
        try
        {
            // Check organization's on-prem sync settings for Seamless SSO
            var org = await _graphClient.Organization
                .GetAsync(r => r.QueryParameters.Select = new[] 
                { 
                    "id", "displayName", "onPremisesSyncEnabled" 
                }, cancellationToken);

            if (org?.Value?.FirstOrDefault()?.OnPremisesSyncEnabled != true)
            {
                // No hybrid setup, Seamless SSO not applicable
                return;
            }

            // Get sync configuration to check Seamless SSO status
            var response = await _httpClient.GetAsync(
                "https://graph.microsoft.com/beta/directory/onPremisesSynchronization",
                cancellationToken);

            if (!response.IsSuccessStatusCode) return;

            var content = await response.Content.ReadAsStringAsync(cancellationToken);
            
            // Check if Seamless SSO is enabled
            if (content.Contains("\"seamlessSingleSignOnEnabled\":true", StringComparison.OrdinalIgnoreCase) ||
                content.Contains("\"isSeamlessSsoEnabled\":true", StringComparison.OrdinalIgnoreCase))
            {
                result.Findings.Add(new BackdoorFinding
                {
                    Type = BackdoorType.SeamlessSsoBackdoor,
                    Severity = SeverityLevel.Medium,
                    Title = "Seamless SSO Enabled - AZUREADSSOACC Account Risk",
                    Description = "Seamless SSO is enabled which uses the AZUREADSSOACC computer account. " +
                                  "If an attacker compromises this account's Kerberos key, they can forge tickets " +
                                  "and authenticate as any user without credentials.",
                    AffectedResource = "AZUREADSSOACC",
                    ResourceId = "SeamlessSSO",
                    Details = new Dictionary<string, string>
                    {
                        { "Feature", "Seamless Single Sign-On" },
                        { "RiskAccount", "AZUREADSSOACC$" },
                        { "AttackTool", "AADInternals - Get-AADIntDesktopSSOAccountPassword" }
                    },
                    Recommendation = "1. Rotate AZUREADSSOACC password regularly (every 30 days). " +
                                     "2. Monitor for DCSync attacks against this account. " +
                                     "3. Consider disabling if not required.",
                    MitreAttackTechnique = "T1558.003 - Kerberoasting"
                });
            }
        }
        catch (Exception)
        {
            result.Errors.Add("Failed to scan Seamless SSO configuration.");
        }
    }

    /// <summary>
    /// Scan device registrations for PRT theft risks
    /// </summary>
    private async Task ScanDeviceRegistrationsAsync(ExtendedBackdoorScanResult result, CancellationToken cancellationToken)
    {
        try
        {
            var devices = await _graphClient.Devices
                .GetAsync(r =>
                {
                    r.QueryParameters.Select = new[] 
                    { 
                        "id", "displayName", "operatingSystem", "operatingSystemVersion",
                        "trustType", "registrationDateTime", "approximateLastSignInDateTime",
                        "isCompliant", "isManaged", "deviceId"
                    };
                    r.QueryParameters.Top = 999;
                }, cancellationToken);

            if (devices?.Value == null) return;

            var recentThreshold = DateTime.UtcNow.AddDays(-7);
            var staleThreshold = DateTime.UtcNow.AddDays(-90);

            foreach (var device in devices.Value)
            {
                var riskIndicators = new List<string>();

                // Check for recently registered devices
                if (device.RegistrationDateTime > recentThreshold)
                {
                    riskIndicators.Add("Recently registered (< 7 days)");
                }

                // Check for suspicious device names
                var nameLower = device.DisplayName?.ToLowerInvariant() ?? "";
                if (nameLower.Contains("test") || nameLower.Contains("temp") || 
                    nameLower.Contains("hack") || nameLower.Contains("attack") ||
                    nameLower.Contains("mimikatz") || nameLower.Contains("kali"))
                {
                    riskIndicators.Add("Suspicious device name");
                }

                // Check for orphaned devices (registered but never signed in)
                if (device.RegistrationDateTime.HasValue && 
                    device.ApproximateLastSignInDateTime == null)
                {
                    riskIndicators.Add("Never signed in after registration");
                }

                // Check for non-compliant Azure AD joined devices
                if (device.TrustType == "AzureAd" && device.IsCompliant == false && device.IsManaged == false)
                {
                    riskIndicators.Add("Azure AD joined but non-compliant and unmanaged");
                }

                // Check for Workplace Join from unusual OS
                if (device.TrustType == "Workplace" && 
                    device.OperatingSystem?.Contains("Linux", StringComparison.OrdinalIgnoreCase) == true)
                {
                    riskIndicators.Add("Workplace joined Linux device (unusual)");
                }

                if (riskIndicators.Count >= 2 || riskIndicators.Any(r => r.Contains("Suspicious device name")))
                {
                    var severity = riskIndicators.Any(r => r.Contains("Suspicious")) 
                        ? SeverityLevel.High 
                        : SeverityLevel.Medium;

                    result.Findings.Add(new BackdoorFinding
                    {
                        Type = BackdoorType.RogueDeviceRegistration,
                        Severity = severity,
                        Title = $"Suspicious Device Registration: {device.DisplayName}",
                        Description = "This device has multiple risk indicators that could suggest " +
                                      "rogue registration for Primary Refresh Token (PRT) theft.",
                        AffectedResource = device.DisplayName,
                        ResourceId = device.DeviceId,
                        Details = new Dictionary<string, string>
                        {
                            { "DeviceId", device.DeviceId ?? "" },
                            { "OS", device.OperatingSystem ?? "Unknown" },
                            { "TrustType", device.TrustType ?? "Unknown" },
                            { "RegisteredOn", device.RegistrationDateTime?.ToString("u") ?? "Unknown" },
                            { "RiskIndicators", string.Join("; ", riskIndicators) }
                        },
                        Recommendation = "1. Verify this device is legitimate. " +
                                         "2. Remove if unauthorized. " +
                                         "3. Review sign-in logs for this device.",
                        MitreAttackTechnique = "T1098.005 - Device Registration"
                    });
                }
            }
        }
        catch (Exception)
        {
            result.Errors.Add("Failed to scan device registrations.");
        }
    }

    #endregion

    #region Federated Identity Credential Detection

    private static readonly HashSet<string> KnownLegitimateIssuers = new(StringComparer.OrdinalIgnoreCase)
    {
        "https://token.actions.githubusercontent.com",
        "https://vstoken.dev.azure.com",
        "https://app.terraform.io",
        "https://gitlab.com",
        "https://kubernetes.default.svc",
        "https://oidc.eks.amazonaws.com",
        "https://container.googleapis.com",
        "https://accounts.google.com"
    };

    private static readonly string[] SuspiciousSubjectPatterns = new[]
    {
        "*", // Wildcard - extremely dangerous
        "repo:*/*", // Overly permissive GitHub pattern
        "project_path:*/*", // Overly permissive GitLab pattern  
        "test", "temp", "backdoor", "debug", "admin",
        "pull_request", // PR-triggered actions can be exploited
    };

    /// <summary>
    /// Scans for suspicious Federated Identity Credentials on app registrations
    /// </summary>
    public async Task ScanFederatedIdentityCredentialsAsync(ExtendedBackdoorScanResult result, CancellationToken cancellationToken = default)
    {
        var graphClient = GraphClient;
        if (graphClient == null) return;

        try
        {
            // Get all applications with their federated identity credentials
            var applications = await graphClient.Applications
                .GetAsync(config =>
                {
                    config.QueryParameters.Select = new[] { "id", "appId", "displayName", "createdDateTime" };
                    config.QueryParameters.Top = 999;
                }, cancellationToken);

            if (applications?.Value == null) return;

            foreach (var app in applications.Value)
            {
                if (app.Id == null) continue;

                try
                {
                    // Get federated identity credentials for this app
                    var fics = await graphClient.Applications[app.Id].FederatedIdentityCredentials
                        .GetAsync(cancellationToken: cancellationToken);

                    if (fics?.Value == null || fics.Value.Count == 0) continue;

                    foreach (var fic in fics.Value)
                    {
                        AnalyzeFederatedIdentityCredential(result, app, fic);
                    }
                }
                catch
                {
                    // Skip apps we can't read FICs for
                }
            }
        }
        catch
        {
            // Scan failed - logged elsewhere
        }
    }

    private void AnalyzeFederatedIdentityCredential(
        ExtendedBackdoorScanResult result,
        Microsoft.Graph.Models.Application app,
        Microsoft.Graph.Models.FederatedIdentityCredential fic)
    {
        var findings = new List<string>();
        var severity = SeverityLevel.Medium;
        var backdoorType = BackdoorType.FederatedIdentityCredentialBackdoor;

        // Check 1: Unknown or suspicious issuer
        var issuer = fic.Issuer ?? "";
        var isKnownIssuer = KnownLegitimateIssuers.Any(k => issuer.StartsWith(k, StringComparison.OrdinalIgnoreCase));
        
        if (!isKnownIssuer && !string.IsNullOrEmpty(issuer))
        {
            findings.Add($"Unknown issuer: {issuer}");
            backdoorType = BackdoorType.FederatedIdentityCredentialUnknownIssuer;
            severity = SeverityLevel.High;
        }

        // Check 2: Suspicious subject patterns (overly permissive)
        var subject = fic.Subject ?? "";
        foreach (var pattern in SuspiciousSubjectPatterns)
        {
            if (subject.Contains(pattern, StringComparison.OrdinalIgnoreCase))
            {
                findings.Add($"Suspicious subject pattern: '{pattern}' in '{subject}'");
                backdoorType = BackdoorType.FederatedIdentityCredentialMisconfigured;
                severity = SeverityLevel.Critical;
                break;
            }
        }

        // Check 3: Wildcard in subject (extremely dangerous)
        if (subject == "*" || subject.EndsWith(":*") || subject.Contains("*/*"))
        {
            findings.Add("Wildcard subject allows any entity to assume this identity");
            severity = SeverityLevel.Critical;
        }

        // Check 4: Pull request triggers (can be exploited by external contributors)
        if (subject.Contains("pull_request", StringComparison.OrdinalIgnoreCase) ||
            subject.Contains("pull-request", StringComparison.OrdinalIgnoreCase))
        {
            findings.Add("FIC allows pull request triggers - external contributors may exploit this");
            severity = SeverityLevel.High;
        }

        // Check 5: Recently created FIC (potential indicator of compromise)
        // Note: FIC doesn't have createdDateTime, so we check the app's creation date
        if (app.CreatedDateTime.HasValue && app.CreatedDateTime.Value > DateTimeOffset.UtcNow.AddDays(-7))
        {
            findings.Add($"App with FIC created recently: {app.CreatedDateTime.Value:yyyy-MM-dd}");
            if (severity < SeverityLevel.High) severity = SeverityLevel.High;
        }

        // Check 6: Suspicious audience values
        var audiences = fic.Audiences ?? new List<string>();
        foreach (var audience in audiences)
        {
            if (audience.Contains("*") || audience == "api://AzureADTokenExchange")
            {
                // api://AzureADTokenExchange is normal, but wildcard is not
                if (audience.Contains("*"))
                {
                    findings.Add($"Wildcard audience: {audience}");
                    severity = SeverityLevel.Critical;
                }
            }
        }

        // Check 7: GitHub Actions with ref:refs/heads/* (any branch)
        if (issuer.Contains("github", StringComparison.OrdinalIgnoreCase) &&
            subject.Contains("ref:refs/heads/*", StringComparison.OrdinalIgnoreCase))
        {
            findings.Add("GitHub FIC allows any branch - should restrict to specific branches like 'main'");
            if (severity < SeverityLevel.High) severity = SeverityLevel.High;
        }

        // Only report if we found issues
        if (findings.Count > 0)
        {
            result.Findings.Add(new BackdoorFinding
            {
                Type = backdoorType,
                Severity = severity,
                Title = $"Suspicious Federated Identity Credential on app: {app.DisplayName ?? app.Id}",
                Description = $"The application has a federated identity credential with concerning configuration: {string.Join("; ", findings)}. " +
                             "Attackers can use misconfigured FICs to impersonate workload identities from external CI/CD pipelines or cloud environments.",
                AffectedResource = app.DisplayName ?? app.AppId ?? app.Id ?? "Unknown",
                ResourceId = app.Id ?? "",
                Details = new Dictionary<string, string>
                {
                    ["AppId"] = app.AppId ?? "",
                    ["AppObjectId"] = app.Id ?? "",
                    ["AppDisplayName"] = app.DisplayName ?? "",
                    ["FicName"] = fic.Name ?? "",
                    ["FicId"] = fic.Id ?? "",
                    ["Issuer"] = issuer,
                    ["Subject"] = subject,
                    ["Audiences"] = string.Join(", ", audiences),
                    ["Findings"] = string.Join("; ", findings)
                },
                Recommendation = "Review and restrict the federated identity credential: " +
                                "1) Use specific subject claims instead of wildcards; " +
                                "2) Restrict to specific branches (e.g., 'ref:refs/heads/main'); " +
                                "3) Verify the issuer is expected; " +
                                "4) Remove FICs that are no longer needed. " +
                                "If unauthorized, delete the FIC immediately.",
                MitreAttackTechnique = "T1550.001 - Use Alternate Authentication Material: Application Access Token"
            });
        }
    }

    /// <summary>
    /// Removes a federated identity credential from an application
    /// </summary>
    public async Task<bool> RemoveFederatedIdentityCredentialAsync(string appObjectId, string ficId, CancellationToken cancellationToken = default)
    {
        var graphClient = GraphClient;
        if (graphClient == null) return false;

        try
        {
            await graphClient.Applications[appObjectId].FederatedIdentityCredentials[ficId]
                .DeleteAsync(cancellationToken: cancellationToken);
            return true;
        }
        catch
        {
            return false;
        }
    }

    #endregion

    // Renamed methods for consistency with new wrapper method
    private async Task ScanDelegatedAdminRelationshipsAsync(
        ExtendedBackdoorScanResult result, 
        CancellationToken cancellationToken)
    {
        try
        {
            // Check for GDAP relationships
            var gdapRelationships = await GraphClient.TenantRelationships.DelegatedAdminRelationships
                .GetAsync(r => r.QueryParameters.Top = 100, cancellationToken);

            if (gdapRelationships?.Value != null)
            {
                foreach (var relationship in gdapRelationships.Value)
                {
                    var partnerName = relationship.Customer?.DisplayName ?? "Unknown Partner";
                    var status = relationship.Status?.ToString() ?? "Unknown";
                    var duration = relationship.Duration;
                    var createdDate = relationship.CreatedDateTime;
                    var endDate = relationship.EndDateTime;
                    
                    // Get assigned roles
                    var accessAssignments = await GraphClient.TenantRelationships
                        .DelegatedAdminRelationships[relationship.Id]
                        .AccessAssignments
                        .GetAsync(cancellationToken: cancellationToken);

                    var roles = new List<string>();
                    if (accessAssignments?.Value != null)
                    {
                        foreach (var assignment in accessAssignments.Value)
                        {
                            if (assignment.AccessContainer?.AccessContainerType?.ToString() == "securityGroup")
                            {
                                var roleDefinitions = assignment.AccessDetails?.UnifiedRoles;
                                if (roleDefinitions != null)
                                {
                                    roles.AddRange(roleDefinitions.Select(r => r.RoleDefinitionId ?? "Unknown"));
                                }
                            }
                        }
                    }

                    // Check for high-privilege roles
                    var dangerousRoles = new[]
                    {
                        "62e90394-69f5-4237-9190-012177145e10", // Global Administrator
                        "e8611ab8-c189-46e8-94e1-60213ab1f814", // Privileged Role Administrator
                        "194ae4cb-b126-40b2-bd5b-6091b380977d", // Security Administrator
                        "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3", // Application Administrator
                        "158c047a-c907-4556-b7ef-446551a6b5f7", // Cloud Application Administrator
                        "b1be1c3e-b65d-4f19-8427-f6fa0d97feb9", // Conditional Access Administrator
                        "29232cdf-9323-42fd-ade2-1d097af3e4de", // Exchange Administrator
                        "f28a1f50-f6e7-4571-818b-6a12f2af6b6c", // SharePoint Administrator
                        "fe930be7-5e62-47db-91af-98c3a49a38b1", // User Administrator
                        "7be44c8a-adaf-4e2a-84d6-ab2649e08a13"  // Privileged Authentication Administrator
                    };

                    var hasHighPrivilege = roles.Any(r => dangerousRoles.Contains(r));
                    var severity = hasHighPrivilege ? SeverityLevel.Critical : SeverityLevel.High;

                    // Check if relationship is still active
                    if (status == "Active" || status == "Approved")
                    {
                        result.Findings.Add(new BackdoorFinding
                        {
                            Type = BackdoorType.DelegatedAdminRelationship,
                            Severity = severity,
                            Title = $"Active GDAP Relationship: {partnerName}",
                            Description = $"Partner '{partnerName}' has delegated admin access to your tenant via GDAP. " +
                                          $"Status: {status}, Created: {createdDate:yyyy-MM-dd}, Expires: {endDate:yyyy-MM-dd}. " +
                                          $"Assigned roles: {(roles.Any() ? string.Join(", ", roles.Take(5)) : "Unknown")}",
                            ResourceId = relationship.Id ?? "",
                            ResourceName = partnerName,
                            AffectedResource = $"Tenant Relationship - {partnerName}",
                            TechnicalDetails = $"GDAP ID: {relationship.Id}, Duration: {duration}, Roles: {roles.Count}",
                            MitreAttackId = "T1199",
                            Recommendation = hasHighPrivilege 
                                ? "CRITICAL: Review this GDAP relationship immediately. Partner has high-privilege roles. " +
                                  "Consider reducing scope to least-privilege or terminating if not needed."
                                : "Review this GDAP relationship and ensure it follows least-privilege principles. " +
                                  "Verify the partner organization is legitimate and access is still required.",
                            DetectedAt = DateTime.UtcNow,
                            CanRemediate = true
                        });
                    }
                }
            }
        }
        catch (Exception)
        {
            // GDAP API may not be available or user lacks permissions
            result.Errors.Add("Unable to scan GDAP relationships. Ensure you have the necessary permissions.");
        }
    }

    // Renamed method for consistency with new wrapper method
    private async Task ScanCrossTenantAccessPoliciesAsync(
        ExtendedBackdoorScanResult result,
        CancellationToken cancellationToken)
    {
        try
        {
            // Get cross-tenant access policy
            var policy = await GraphClient.Policies.CrossTenantAccessPolicy
                .GetAsync(cancellationToken: cancellationToken);

            // Get partner configurations
            var partners = await GraphClient.Policies.CrossTenantAccessPolicy.Partners
                .GetAsync(r => r.QueryParameters.Top = 100, cancellationToken);

            if (partners?.Value != null)
            {
                foreach (var partner in partners.Value)
                {
                    var tenantId = partner.TenantId ?? "Unknown";
                    var inboundTrust = partner.InboundTrust;

                    // Check if trusting external MFA
                    if (inboundTrust?.IsMfaAccepted == true)
                    {
                        result.Findings.Add(new BackdoorFinding
                        {
                            Type = BackdoorType.CrossTenantAccessTrustMfa,
                            Severity = SeverityLevel.High,
                            Title = $"Cross-Tenant MFA Trust: {tenantId}",
                            Description = $"Your tenant trusts MFA claims from external tenant '{tenantId}'. " +
                                          "This means users from that tenant can bypass your MFA requirements " +
                                          "if they've completed MFA in their home tenant. If that tenant is compromised, " +
                                          "attackers could access your resources without completing your MFA.",
                            ResourceId = tenantId,
                            ResourceName = $"Cross-Tenant Policy - {tenantId}",
                            AffectedResource = "Cross-Tenant Access Policy",
                            TechnicalDetails = $"Partner Tenant: {tenantId}, IsMfaAccepted: true",
                            MitreAttackId = "T1556.006",
                            Recommendation = "Review if this trust is necessary. MFA trust should only be configured " +
                                             "for M&A scenarios or highly trusted partner organizations. Consider removing " +
                                             "MFA trust and requiring MFA in your tenant.",
                            DetectedAt = DateTime.UtcNow,
                            CanRemediate = true
                        });
                    }

                    // Check if trusting device compliance
                    if (inboundTrust?.IsCompliantDeviceAccepted == true)
                    {
                        result.Findings.Add(new BackdoorFinding
                        {
                            Type = BackdoorType.CrossTenantAccessTrustDevice,
                            Severity = SeverityLevel.High,
                            Title = $"Cross-Tenant Device Compliance Trust: {tenantId}",
                            Description = $"Your tenant trusts device compliance claims from external tenant '{tenantId}'. " +
                                          "This means users from that tenant can satisfy your device compliance requirements " +
                                          "based on their tenant's Intune policies, which you don't control.",
                            ResourceId = tenantId,
                            ResourceName = $"Cross-Tenant Policy - {tenantId}",
                            AffectedResource = "Cross-Tenant Access Policy",
                            TechnicalDetails = $"Partner Tenant: {tenantId}, IsCompliantDeviceAccepted: true",
                            MitreAttackId = "T1199",
                            Recommendation = "Review if device compliance trust is necessary. Only enable for M&A " +
                                             "scenarios where you have verified the partner's Intune policies meet your standards.",
                            DetectedAt = DateTime.UtcNow,
                            CanRemediate = true
                        });
                    }

                    // Check if trusting Hybrid Azure AD Join
                    if (inboundTrust?.IsHybridAzureADJoinedDeviceAccepted == true)
                    {
                        result.Findings.Add(new BackdoorFinding
                        {
                            Type = BackdoorType.CrossTenantAccessTrustHybridJoin,
                            Severity = SeverityLevel.Critical,
                            Title = $"Cross-Tenant Hybrid Join Trust: {tenantId}",
                            Description = $"Your tenant trusts Hybrid Azure AD Join claims from external tenant '{tenantId}'. " +
                                          "This is DANGEROUS because HAADJ devices are controlled by the partner's on-premises AD. " +
                                          "If their AD is compromised, attackers could create devices that satisfy your CA policies.",
                            ResourceId = tenantId,
                            ResourceName = $"Cross-Tenant Policy - {tenantId}",
                            AffectedResource = "Cross-Tenant Access Policy",
                            TechnicalDetails = $"Partner Tenant: {tenantId}, IsHybridAzureADJoinedDeviceAccepted: true",
                            MitreAttackId = "T1199",
                            Recommendation = "CRITICAL: Remove Hybrid Azure AD Join trust immediately unless absolutely necessary. " +
                                             "HAADJ trust extends your trust boundary to include the partner's on-premises AD infrastructure.",
                            DetectedAt = DateTime.UtcNow,
                            CanRemediate = true
                        });
                    }
                }
            }

            // Check default policy settings
            var defaultPolicy = await GraphClient.Policies.CrossTenantAccessPolicy.Default
                .GetAsync(cancellationToken: cancellationToken);

            if (defaultPolicy?.InboundTrust != null)
            {
                var trust = defaultPolicy.InboundTrust;
                if (trust.IsMfaAccepted == true || trust.IsCompliantDeviceAccepted == true || 
                    trust.IsHybridAzureADJoinedDeviceAccepted == true)
                {
                    result.Findings.Add(new BackdoorFinding
                    {
                        Type = BackdoorType.CrossTenantAccessTrustMfa,
                        Severity = SeverityLevel.Critical,
                        Title = "Default Cross-Tenant Trust Enabled for ALL External Tenants",
                        Description = "Your DEFAULT cross-tenant policy trusts claims from ALL external tenants! " +
                                      $"MFA: {trust.IsMfaAccepted}, Device Compliance: {trust.IsCompliantDeviceAccepted}, " +
                                      $"Hybrid Join: {trust.IsHybridAzureADJoinedDeviceAccepted}. " +
                                      "This is extremely dangerous as any external user could bypass your security controls.",
                        ResourceId = "default",
                        ResourceName = "Default Cross-Tenant Policy",
                        AffectedResource = "Cross-Tenant Access Policy - Default",
                        TechnicalDetails = $"IsMfaAccepted: {trust.IsMfaAccepted}, IsCompliantDeviceAccepted: {trust.IsCompliantDeviceAccepted}, " +
                                           $"IsHybridAzureADJoinedDeviceAccepted: {trust.IsHybridAzureADJoinedDeviceAccepted}",
                        MitreAttackId = "T1556.006",
                        Recommendation = "CRITICAL: Disable all trust settings in the default cross-tenant policy immediately. " +
                                         "Configure trust only for specific partner tenants that require it.",
                        DetectedAt = DateTime.UtcNow,
                        CanRemediate = true
                    });
                }
            }
        }
        catch (Exception)
        {
            result.Errors.Add("Unable to scan cross-tenant access policies. Ensure you have the necessary permissions.");
        }
    }

    // Renamed method for consistency with new wrapper method
    private async Task ScanGuestUsersWithAdminRolesAsync(
        ExtendedBackdoorScanResult result,
        CancellationToken cancellationToken)
    {
        try
        {
            // Get all directory roles
            var roles = await GraphClient.DirectoryRoles
                .GetAsync(r => r.QueryParameters.Expand = new[] { "members" }, cancellationToken);

            if (roles?.Value == null) return;

            // High-privilege role IDs to check
            var privilegedRoleTemplates = new Dictionary<string, string>
            {
                { "62e90394-69f5-4237-9190-012177145e10", "Global Administrator" },
                { "e8611ab8-c189-46e8-94e1-60213ab1f814", "Privileged Role Administrator" },
                { "194ae4cb-b126-40b2-bd5b-6091b380977d", "Security Administrator" },
                { "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3", "Application Administrator" },
                { "158c047a-c907-4556-b7ef-446551a6b5f7", "Cloud Application Administrator" },
                { "b1be1c3e-b65d-4f19-8427-f6fa0d97feb9", "Conditional Access Administrator" },
                { "29232cdf-9323-42fd-ade2-1d097af3e4de", "Exchange Administrator" },
                { "f28a1f50-f6e7-4571-818b-6a12f2af6b6c", "SharePoint Administrator" },
                { "fe930be7-5e62-47db-91af-98c3a49a38b1", "User Administrator" },
                { "7be44c8a-adaf-4e2a-84d6-ab2649e08a13", "Privileged Authentication Administrator" },
                { "e00e864a-17c5-4a4b-9c06-f5b95a8d5bd8", "Billing Administrator" },
                { "fdd7a751-b60b-444a-984c-02652fe8fa1c", "Groups Administrator" },
                { "11648597-926c-4cf3-9c36-bcebb0ba8dcc", "Power Platform Administrator" },
                { "69091246-20e8-4a56-aa4d-066075b2a7a8", "Teams Administrator" },
                { "baf37b3a-610e-45da-9e62-d9d1e5e8914b", "Teams Communications Administrator" }
            };

            foreach (var role in roles.Value)
            {
                var roleTemplateId = role.RoleTemplateId;
                if (roleTemplateId == null || !privilegedRoleTemplates.ContainsKey(roleTemplateId))
                    continue;

                var roleName = privilegedRoleTemplates[roleTemplateId];

                // Get members with their user type
                var members = await GraphClient.DirectoryRoles[role.Id].Members
                    .GetAsync(cancellationToken: cancellationToken);

                if (members?.Value == null) continue;

                foreach (var member in members.Value)
                {
                    // Check if member is a user
                    if (member.OdataType != "#microsoft.graph.user") continue;

                    // Get full user details to check userType
                    try
                    {
                        var user = await GraphClient.Users[member.Id]
                            .GetAsync(r => r.QueryParameters.Select = new[] 
                            { 
                                "id", "displayName", "userPrincipalName", "userType", 
                                "createdDateTime", "externalUserState" 
                            }, cancellationToken);

                        if (user?.UserType == "Guest")
                        {
                            var severity = roleTemplateId == "62e90394-69f5-4237-9190-012177145e10" 
                                ? SeverityLevel.Critical  // Global Admin
                                : SeverityLevel.High;

                            result.Findings.Add(new BackdoorFinding
                            {
                                Type = BackdoorType.GuestUserWithAdminRole,
                                Severity = severity,
                                Title = $"Guest User with {roleName} Role",
                                Description = $"External guest user '{user.DisplayName}' ({user.UserPrincipalName}) " +
                                              $"has the '{roleName}' role. Guest users are controlled by their home tenant. " +
                                              $"If their home tenant is compromised, this admin access could be abused.",
                                ResourceId = user.Id ?? "",
                                ResourceName = user.DisplayName ?? "Unknown",
                                AffectedResource = $"User: {user.UserPrincipalName}",
                                TechnicalDetails = $"UserType: Guest, Role: {roleName}, Created: {user.CreatedDateTime:yyyy-MM-dd}, " +
                                                   $"ExternalUserState: {user.ExternalUserState}",
                                MitreAttackId = "T1078.004",
                                Recommendation = severity == SeverityLevel.Critical
                                    ? "CRITICAL: Remove Global Administrator role from guest user immediately. " +
                                      "Create a dedicated member account for external admins if needed."
                                    : $"Review if this guest user needs '{roleName}' access. Consider creating a dedicated " +
                                      "member account or using PIM for time-limited access.",
                                DetectedAt = DateTime.UtcNow,
                                CanRemediate = true
                            });
                        }
                    }
                    catch
                    {
                        // Skip if can't get user details
                    }
                }
            }
        }
        catch (Exception)
        {
            result.Errors.Add("Unable to scan guest users with admin roles. Ensure you have the necessary permissions.");
        }
    }

    #endregion

    #region Remediation Methods

    public async Task<(bool Success, string Message)> RemoveCrossTenantTrustAsync(
        string tenantId,
        CancellationToken cancellationToken = default)
    {
        try
        {
            if (tenantId == "default")
            {
                // Reset default policy to not trust any external claims
                var updatePolicy = new Microsoft.Graph.Models.CrossTenantAccessPolicyConfigurationDefault
                {
                    InboundTrust = new Microsoft.Graph.Models.CrossTenantAccessPolicyInboundTrust
                    {
                        IsMfaAccepted = false,
                        IsCompliantDeviceAccepted = false,
                        IsHybridAzureADJoinedDeviceAccepted = false
                    }
                };

                await GraphClient.Policies.CrossTenantAccessPolicy.Default
                    .PatchAsync(updatePolicy, cancellationToken: cancellationToken);

                return (true, "Default cross-tenant trust settings have been disabled.");
            }
            else
            {
                // Update specific partner configuration
                var updatePartner = new Microsoft.Graph.Models.CrossTenantAccessPolicyConfigurationPartner
                {
                    InboundTrust = new Microsoft.Graph.Models.CrossTenantAccessPolicyInboundTrust
                    {
                        IsMfaAccepted = false,
                        IsCompliantDeviceAccepted = false,
                        IsHybridAzureADJoinedDeviceAccepted = false
                    }
                };

                await GraphClient.Policies.CrossTenantAccessPolicy.Partners[tenantId]
                    .PatchAsync(updatePartner, cancellationToken: cancellationToken);

                return (true, $"Cross-tenant trust settings for tenant '{tenantId}' have been disabled.");
            }
        }
        catch (Exception)
        {
            return (false, "Failed to update cross-tenant trust settings. Check permissions.");
        }
    }

    public async Task<(bool Success, string Message)> RemoveGuestFromAdminRoleAsync(
        string userId,
        string roleId, // Note: This is not directly used here as we iterate roles to find the correct one.
        CancellationToken cancellationToken = default)
    {
        try
        {
            // Find the directory role assignment and remove it
            var roles = await GraphClient.DirectoryRoles
                .GetAsync(cancellationToken: cancellationToken);

            if (roles?.Value != null)
            {
                foreach (var role in roles.Value)
                {
                    // Check if this is the role we want to remove the user from.
                    // The roleId from TechnicalDetails in BackdoorFinding is not the role's actual ID,
                    // but the RoleTemplateId. We need to find the role by its ID/TemplateId.
                    // A better approach might be to pass the actual role ID to this method.
                    // For now, we'll just find the first role that contains the user as a member.
                    // A more robust solution would involve mapping the roleTemplateId to the role.Id.

                    // Get members for the current role
                    var members = await GraphClient.DirectoryRoles[role.Id].Members
                        .GetAsync(cancellationToken: cancellationToken);

                    if (members?.Value?.Any(m => m.Id == userId) == true)
                    {
                        // Found the role the user is a member of. Remove the user from this role.
                        await GraphClient.DirectoryRoles[role.Id].Members[userId].Ref
                            .DeleteAsync(cancellationToken: cancellationToken);

                        return (true, $"Successfully removed guest user from admin role.");
                    }
                }
            }

            return (false, "Could not find role assignment to remove.");
        }
        catch (Exception)
        {
            return (false, "Failed to remove guest user from admin role. Check permissions.");
        }
    }

    /// <summary>
    /// Remediate a backdoor finding based on its type
    /// </summary>
    public async Task<(bool Success, string Message)> RemediateBackdoorAsync(
        BackdoorFinding finding,
        CancellationToken cancellationToken = default)
    {
        return finding.Type switch
        {
            BackdoorType.FederatedDomainBackdoor => await RevokeFederationBackdoorAsync(
                finding.ResourceId ?? finding.AffectedResource ?? "",
                finding.Details?.GetValueOrDefault("FederationConfigId"),
                cancellationToken),
            
            BackdoorType.FederationMfaBypass => await FixFederationMfaBypassAsync(
                finding.ResourceId ?? finding.AffectedResource ?? "",
                cancellationToken),
            
            BackdoorType.SecondarySigningCertificate => await RemoveSecondarySigningCertificateAsync(
                finding.ResourceId ?? finding.AffectedResource ?? "",
                cancellationToken),
            
            BackdoorType.SuspiciousSigningCertificate => await RevokeFederationBackdoorAsync(
                finding.ResourceId ?? finding.AffectedResource ?? "",
                finding.Details?.GetValueOrDefault("FederationConfigId"), // May need to get config ID if not present
                cancellationToken),

            BackdoorType.SuspiciousServicePrincipal => await DeleteServicePrincipalAsync(
                finding.ResourceId ?? "",
                cancellationToken),
            
            BackdoorType.AdminConsentGrant => await RevokeOAuthGrantAsync(
                finding.ResourceId ?? "",
                cancellationToken),

            BackdoorType.FociTokenAbuse => new FederationRevocationResult // No direct remediation, provide guidance
            {
                Success = false,
                DomainId = finding.ResourceId ?? "",
                Message = $"Remediation requires manual review for FOCI token abuse.",
                ErrorDetails = "Review the FOCI app's scopes and consent. Monitor sign-in logs."
            },

            BackdoorType.SuspiciousRedirectUri => new FederationRevocationResult // No direct remediation, provide guidance
            {
                Success = false,
                DomainId = finding.ResourceId ?? "",
                Message = $"Remediation requires manual review for suspicious redirect URIs.",
                ErrorDetails = "Update the application's redirect URIs to secure endpoints."
            },

            BackdoorType.ImplicitFlowEnabled => new FederationRevocationResult // No direct remediation, provide guidance
            {
                Success = false,
                DomainId = finding.ResourceId ?? "",
                Message = $"Remediation requires manual migration for implicit flow apps.",
                ErrorDetails = "Migrate the application to use authorization code flow with PKCE and disable implicit grant."
            },

            BackdoorType.SeamlessSsoBackdoor => new FederationRevocationResult // No direct remediation, provide guidance
            {
                Success = false,
                DomainId = finding.ResourceId ?? "",
                Message = $"Remediation for Seamless SSO involves security best practices.",
                ErrorDetails = "Regularly rotate the AZUREADSSOACC password and monitor for DCSync attacks. Consider disabling if not required."
            },

            BackdoorType.RogueDeviceRegistration => new FederationRevocationResult // No direct remediation, provide guidance
            {
                Success = false,
                DomainId = finding.ResourceId ?? "",
                Message = $"Remediation requires manual verification for rogue device registrations.",
                ErrorDetails = "Verify the device legitimacy and remove if unauthorized. Review sign-in logs."
            },
            
            // Add FIC backdoor types to remediation
            BackdoorType.FederatedIdentityCredentialBackdoor => await RemoveFederatedIdentityCredentialAsync(finding.ResourceId ?? "", finding.Details?.GetValueOrDefault("FicId") ?? "", cancellationToken) ?
                new FederationRevocationResult { Success = true, DomainId = finding.ResourceId ?? "", Message = $"Successfully removed FIC {finding.Details?.GetValueOrDefault("FicId") ?? ""} from app {finding.AffectedResource ?? ""}" } :
                new FederationRevocationResult { Success = false, DomainId = finding.ResourceId ?? "", Message = $"Failed to remove FIC {finding.Details?.GetValueOrDefault("FicId") ?? ""} from app {finding.AffectedResource ?? ""}", ErrorDetails = "Could not remove FIC." },

            BackdoorType.FederatedIdentityCredentialUnknownIssuer => await RemoveFederatedIdentityCredentialAsync(finding.ResourceId ?? "", finding.Details?.GetValueOrDefault("FicId") ?? "", cancellationToken) ?
                new FederationRevocationResult { Success = true, DomainId = finding.ResourceId ?? "", Message = $"Successfully removed FIC {finding.Details?.GetValueOrDefault("FicId") ?? ""} from app {finding.AffectedResource ?? ""}" } :
                new FederationRevocationResult { Success = false, DomainId = finding.ResourceId ?? "", Message = $"Failed to remove FIC {finding.Details?.GetValueOrDefault("FicId") ?? ""} from app {finding.AffectedResource ?? ""}", ErrorDetails = "Could not remove FIC." },

            BackdoorType.FederatedIdentityCredentialMisconfigured => await RemoveFederatedIdentityCredentialAsync(finding.ResourceId ?? "", finding.Details?.GetValueOrDefault("FicId") ?? "", cancellationToken) ?
                new FederationRevocationResult { Success = true, DomainId = finding.ResourceId ?? "", Message = $"Successfully removed FIC {finding.Details?.GetValueOrDefault("FicId") ?? ""} from app {finding.AffectedResource ?? ""}" } :
                new FederationRevocationResult { Success = false, DomainId = finding.ResourceId ?? "", Message = $"Failed to remove FIC {finding.Details?.GetValueOrDefault("FicId") ?? ""} from app {finding.AffectedResource ?? ""}", ErrorDetails = "Could not remove FIC." },
            // </CHANGE>
            
            BackdoorType.CrossTenantAccessTrustMfa or
            BackdoorType.CrossTenantAccessTrustDevice or
            BackdoorType.CrossTenantAccessTrustHybridJoin =>
                await RemoveCrossTenantTrustAsync(finding.ResourceId ?? "", cancellationToken),
            
            BackdoorType.GuestUserWithAdminRole =>
                await RemoveGuestFromAdminRoleAsync(finding.ResourceId ?? "", finding.TechnicalDetails ?? "", cancellationToken),
            
            _ => (false, $"Remediation not supported for {finding.Type}")
        };
    }

    /// <summary>
    /// Delete a suspicious service principal
    /// </summary>
    public async Task<FederationRevocationResult> DeleteServicePrincipalAsync(
        string servicePrincipalId,
        CancellationToken cancellationToken = default)
    {
        try
        {
            await GraphClient.ServicePrincipals[servicePrincipalId]
                .DeleteAsync(cancellationToken: cancellationToken);

            return new FederationRevocationResult
            {
                Success = true,
                DomainId = servicePrincipalId,
                Message = $"Successfully deleted service principal {servicePrincipalId}",
                ConvertedToManaged = false
            };
        }
        catch (TaskCanceledException)
        {
            return new FederationRevocationResult
            {
                Success = false,
                DomainId = servicePrincipalId,
                Message = "Deleting service principal timed out",
                ErrorDetails = "The operation timed out."
            };
        }
        catch (Exception ex)
        {
            return new FederationRevocationResult
            {
                Success = false,
                DomainId = servicePrincipalId,
                Message = "Failed to delete service principal",
                ErrorDetails = ex.Message
            };
        }
    }

    /// <summary>
    /// Revoke an OAuth permission grant
    /// </summary>
    public async Task<FederationRevocationResult> RevokeOAuthGrantAsync(
        string grantId,
        CancellationToken cancellationToken = default)
    {
        try
        {
            await GraphClient.Oauth2PermissionGrants[grantId]
                .DeleteAsync(cancellationToken: cancellationToken);

            return new FederationRevocationResult
            {
                Success = true,
                DomainId = grantId,
                Message = $"Successfully revoked OAuth permission grant {grantId}",
                ConvertedToManaged = false
            };
        }
        catch (TaskCanceledException)
        {
            return new FederationRevocationResult
            {
                Success = false,
                DomainId = grantId,
                Message = "Revoking OAuth grant timed out",
                ErrorDetails = "The operation timed out."
            };
        }
        catch (Exception ex)
        {
            return new FederationRevocationResult
            {
                Success = false,
                DomainId = grantId,
                Message = "Failed to revoke OAuth permission grant",
                ErrorDetails = ex.Message
            };
        }
    }

    /// <summary>
    /// Mass revoke all federation backdoors (original implementation)
    /// </summary>
    public async Task<List<FederationRevocationResult>> MassRevokeFederationBackdoorsAsync(
        IEnumerable<BackdoorFinding> federationFindings,
        Action<int, int>? progressCallback = null,
        CancellationToken cancellationToken = default)
    {
        var results = new List<FederationRevocationResult>();
        var findings = federationFindings.Where(f => f.Type == BackdoorType.FederatedDomainBackdoor).ToList();
        var total = findings.Count;
        var current = 0;

        foreach (var finding in findings)
        {
            cancellationToken.ThrowIfCancellationRequested();

            var domainId = finding.ResourceId ?? finding.AffectedResource;
            var configId = finding.Details?.GetValueOrDefault("FederationConfigId");

            if (!string.IsNullOrEmpty(domainId))
            {
                var result = await RevokeFederationBackdoorAsync(domainId, configId, cancellationToken);
                results.Add(result);
            }
            else
            {
                results.Add(new FederationRevocationResult
                {
                    Success = false,
                    DomainId = domainId ?? "Unknown",
                    Message = "Missing domain ID",
                    ErrorDetails = "Could not determine federation configuration to remove"
                });
            }

            current++;
            progressCallback?.Invoke(current, total);
            
            // Small delay between operations to avoid throttling
            await Task.Delay(500, cancellationToken);
        }

        return results;
    }

    /// <summary>
    /// Mass remediate all federation-related backdoors (expanded to include MFA bypass, secondary certs)
    /// </summary>
    public async Task<List<FederationRevocationResult>> MassRemediateFederationBackdoorsAsync(
        IEnumerable<BackdoorFinding> findings,
        Action<string, int, int>? progressCallback = null,
        CancellationToken cancellationToken = default)
    {
        var results = new List<FederationRevocationResult>();
        
        // Include all federation-related backdoor types
        var federationTypes = new[]
        {
            BackdoorType.FederatedDomainBackdoor,
            BackdoorType.FederationMfaBypass,
            BackdoorType.SecondarySigningCertificate,
            BackdoorType.SuspiciousSigningCertificate
        };
        
        var federationFindings = findings
            .Where(f => federationTypes.Contains(f.Type))
            .ToList();
        
        var total = federationFindings.Count;
        var current = 0;

        foreach (var finding in federationFindings)
        {
            cancellationToken.ThrowIfCancellationRequested();

            var domainId = finding.ResourceId ?? finding.AffectedResource ?? "Unknown";
            progressCallback?.Invoke($"{finding.Type}: {domainId}", current, total);

            var result = await RemediateBackdoorAsync(finding, cancellationToken);
            results.Add(result);

            current++;
            progressCallback?.Invoke($"{finding.Type}: {domainId}", current, total);
            
            // Small delay between operations to avoid throttling
            await Task.Delay(500, cancellationToken);
        }

        return results;
    }

    /// <summary>
    /// Mass remediate all remediatable backdoors
    /// </summary>
    public async Task<List<FederationRevocationResult>> MassRemediateAllBackdoorsAsync(
        IEnumerable<BackdoorFinding> findings,
        Action<string, int, int>? progressCallback = null,
        CancellationToken cancellationToken = default)
    {
        var results = new List<FederationRevocationResult>();
        
        // Backdoor types that can be automatically remediated
        var remediableTypes = new[]
        {
            BackdoorType.FederatedDomainBackdoor,
            BackdoorType.FederationMfaBypass,
            BackdoorType.SecondarySigningCertificate,
            BackdoorType.SuspiciousSigningCertificate,
            BackdoorType.SuspiciousServicePrincipal,
            BackdoorType.AdminConsentGrant,
            // Add FIC backdoor types to remediation
            BackdoorType.FederatedIdentityCredentialBackdoor,
            BackdoorType.FederatedIdentityCredentialUnknownIssuer,
            BackdoorType.FederatedIdentityCredentialMisconfigured,
            // Add cross-tenant and guest user backdoor types
            BackdoorType.CrossTenantAccessTrustMfa,
            BackdoorType.CrossTenantAccessTrustDevice,
            BackdoorType.CrossTenantAccessTrustHybridJoin,
            BackdoorType.GuestUserWithAdminRole
            // </CHANGE>
        };
        
        var remediableFindings = findings
            .Where(f => remediableTypes.Contains(f.Type))
            .OrderByDescending(f => f.Severity) // Critical first
            .ToList();
        
        var total = remediableFindings.Count;
        var current = 0;

        foreach (var finding in remediableFindings)
        {
            cancellationToken.ThrowIfCancellationRequested();

            var resourceName = finding.AffectedResource ?? finding.ResourceId ?? "Unknown";
            progressCallback?.Invoke($"{finding.Type}: {resourceName}", current, total);

            var result = await RemediateBackdoorAsync(finding, cancellationToken);
            results.Add(result);

            current++;
            progressCallback?.Invoke($"{finding.Type}: {resourceName}", current, total);
            
            // Small delay between operations to avoid throttling
            await Task.Delay(500, cancellationToken);
        }

        return results;
    }

    #endregion

    #region IDisposable
    
    public void Dispose()
    {
        Dispose(true);
        GC.SuppressFinalize(this);
    }
    
    protected virtual void Dispose(bool disposing)
    {
        if (!_disposed)
        {
            if (disposing)
            {
                _httpClient?.Dispose();
            }
            _disposed = true;
        }
    }
    
    #endregion
}
