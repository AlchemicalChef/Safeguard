using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Azure.Identity;
using Microsoft.Graph;
using Microsoft.Graph.Models;

namespace Safeguard.Services;

public class AppProvisioningService
{
    // Well-known Microsoft Graph App ID
    private const string MicrosoftGraphAppId = "00000003-0000-0000-c000-000000000000";
    
    // Required Graph API permission IDs (from Microsoft Graph service principal)
    private static readonly Dictionary<string, string> RequiredPermissions = new()
    {
        // Delegated permissions
        { "User.ReadWrite.All", "204e0828-b5ca-4f33-916b-0b3b10b4c64d" },
        { "Directory.ReadWrite.All", "c5366453-9fb0-48a5-a156-24f0c49a4b84" },
        { "UserAuthenticationMethod.ReadWrite.All", "b7887744-6746-4312-813d-72daeaee7e2d" },
        { "Application.ReadWrite.All", "bdfbf15f-ee85-4955-8675-146e8e5296b5" },
        { "Domain.ReadWrite.All", "0b5d694c-a244-4bde-86e6-eb5cd07730fe" },
        { "User.Read", "e1fe6dd8-ba31-4d61-89e7-88639da4683d" },
        { "DelegatedPermissionGrant.ReadWrite.All", "8e8e4742-1d95-4f68-9d56-6ee75648c72a" },
        { "Device.Read.All", "951183d1-1a61-466f-a6d1-1fde911bfd95" },
        { "AuditLog.Read.All", "b0afded3-3588-46d8-8b3d-9842eff778da" }
    };

    public event Action<string>? OnStatusUpdate;
    public event Action<string>? OnError;

    public async Task<AppProvisioningResult> ProvisionSafeguardAppAsync(
        string tenantId,
        CancellationToken cancellationToken = default)
    {
        try
        {
            OnStatusUpdate?.Invoke("Starting interactive authentication...");

            // Use interactive browser authentication with minimal bootstrap scopes
            var credential = new InteractiveBrowserCredential(new InteractiveBrowserCredentialOptions
            {
                TenantId = tenantId == "common" ? null : tenantId,
                ClientId = "14d82eec-204b-4c2f-b7e8-296a70dab67e", // Microsoft Graph PowerShell
                RedirectUri = new Uri("http://localhost")
            });

            var bootstrapScopes = new[] { "Application.ReadWrite.All", "DelegatedPermissionGrant.ReadWrite.All" };
            
            OnStatusUpdate?.Invoke("Opening browser for authentication...");
            
            var graphClient = new GraphServiceClient(credential, bootstrapScopes);

            // Verify authentication works
            OnStatusUpdate?.Invoke("Verifying authentication...");
            var me = await graphClient.Me.GetAsync(cancellationToken: cancellationToken);
            
            if (me == null)
            {
                return new AppProvisioningResult
                {
                    Success = false,
                    ErrorMessage = "Failed to authenticate. Please ensure you have admin privileges."
                };
            }

            OnStatusUpdate?.Invoke($"Authenticated as {me.DisplayName}");

            // Check if Safeguard app already exists
            OnStatusUpdate?.Invoke("Checking for existing Safeguard app registration...");
            var existingApps = await graphClient.Applications
                .GetAsync(r => r.QueryParameters.Filter = "displayName eq 'Safeguard - Entra ID Security Tool'",
                    cancellationToken);

            if (existingApps?.Value?.Count > 0)
            {
                var existingApp = existingApps.Value[0];
                OnStatusUpdate?.Invoke($"Found existing Safeguard app: {existingApp.AppId}");
                
                return new AppProvisioningResult
                {
                    Success = true,
                    ClientId = existingApp.AppId ?? string.Empty,
                    ApplicationObjectId = existingApp.Id ?? string.Empty,
                    DisplayName = existingApp.DisplayName ?? string.Empty,
                    AlreadyExisted = true
                };
            }

            // Create new application registration
            OnStatusUpdate?.Invoke("Creating Safeguard application registration...");
            
            var requiredResourceAccess = new List<RequiredResourceAccess>
            {
                new RequiredResourceAccess
                {
                    ResourceAppId = MicrosoftGraphAppId,
                    ResourceAccess = new List<ResourceAccess>()
                }
            };

            foreach (var permission in RequiredPermissions)
            {
                requiredResourceAccess[0].ResourceAccess!.Add(new ResourceAccess
                {
                    Id = Guid.Parse(permission.Value),
                    Type = "Scope" // Delegated permission
                });
            }

            var newApp = new Application
            {
                DisplayName = "Safeguard - Entra ID Security Tool",
                Description = "Incident response tool for Entra ID token revocation, backdoor detection, and security remediation.",
                SignInAudience = "AzureADMyOrg",
                RequiredResourceAccess = requiredResourceAccess,
                PublicClient = new PublicClientApplication
                {
                    RedirectUris = new List<string>
                    {
                        "http://localhost",
                        "https://login.microsoftonline.com/common/oauth2/nativeclient"
                    }
                },
                IsFallbackPublicClient = true,
                Tags = new List<string>
                {
                    "SecurityTool",
                    "IncidentResponse",
                    "Safeguard"
                }
            };

            var createdApp = await graphClient.Applications.PostAsync(newApp, cancellationToken: cancellationToken);

            if (createdApp == null || string.IsNullOrEmpty(createdApp.AppId))
            {
                return new AppProvisioningResult
                {
                    Success = false,
                    ErrorMessage = "Failed to create application registration"
                };
            }

            OnStatusUpdate?.Invoke($"Application created with Client ID: {createdApp.AppId}");

            OnStatusUpdate?.Invoke("Updating application redirect URIs...");
            var updateApp = new Application
            {
                PublicClient = new PublicClientApplication
                {
                    RedirectUris = new List<string>
                    {
                        "http://localhost",
                        "https://login.microsoftonline.com/common/oauth2/nativeclient",
                        $"ms-appx-web://microsoft.aad.brokerplugin/{createdApp.AppId}"
                    }
                }
            };
            
            await graphClient.Applications[createdApp.Id].PatchAsync(updateApp, cancellationToken: cancellationToken);

            // Create service principal for the app
            OnStatusUpdate?.Invoke("Creating service principal...");
            
            var servicePrincipal = new ServicePrincipal
            {
                AppId = createdApp.AppId,
                DisplayName = createdApp.DisplayName,
                Tags = new List<string> { "WindowsAzureActiveDirectoryIntegratedApp" }
            };

            var createdSp = await graphClient.ServicePrincipals.PostAsync(servicePrincipal, cancellationToken: cancellationToken);

            if (createdSp == null)
            {
                OnStatusUpdate?.Invoke("Warning: Failed to create service principal. Admin consent may require manual setup.");
            }
            else
            {
                OnStatusUpdate?.Invoke($"Service principal created: {createdSp.Id}");

                // Grant admin consent for all permissions
                OnStatusUpdate?.Invoke("Granting admin consent for permissions...");
                
                try
                {
                    await GrantAdminConsentAsync(graphClient, createdSp.Id!, tenantId, cancellationToken);
                    OnStatusUpdate?.Invoke("Admin consent granted successfully");
                }
                catch
                {
                    OnStatusUpdate?.Invoke("Warning: Could not auto-grant consent. Manual consent may be required.");
                }
            }

            return new AppProvisioningResult
            {
                Success = true,
                ClientId = createdApp.AppId,
                ApplicationObjectId = createdApp.Id ?? string.Empty,
                ServicePrincipalId = createdSp?.Id,
                DisplayName = createdApp.DisplayName ?? string.Empty,
                AlreadyExisted = false
            };
        }
        catch (AuthenticationFailedException)
        {
            OnError?.Invoke("Authentication failed");
            return new AppProvisioningResult
            {
                Success = false,
                ErrorMessage = "Authentication failed. Please ensure you're signing in with a Global Administrator account."
            };
        }
        catch (ServiceException)
        {
            OnError?.Invoke("Graph API error during provisioning");
            return new AppProvisioningResult
            {
                Success = false,
                ErrorMessage = "Failed to provision application. Please check your permissions and try again."
            };
        }
        catch
        {
            OnError?.Invoke("Unexpected error during provisioning");
            return new AppProvisioningResult
            {
                Success = false,
                ErrorMessage = "An unexpected error occurred during provisioning."
            };
        }
    }

    private async Task GrantAdminConsentAsync(
        GraphServiceClient graphClient,
        string servicePrincipalId,
        string tenantId,
        CancellationToken cancellationToken)
    {
        // Get Microsoft Graph service principal
        var graphSpResponse = await graphClient.ServicePrincipals
            .GetAsync(r => r.QueryParameters.Filter = $"appId eq '{MicrosoftGraphAppId}'",
                cancellationToken);

        var graphSp = graphSpResponse?.Value?.Count > 0 ? graphSpResponse.Value[0] : null;
        
        if (graphSp == null)
        {
            throw new InvalidOperationException("Could not find Microsoft Graph service principal");
        }

        // Build scope string for all delegated permissions
        var scopes = string.Join(" ", RequiredPermissions.Keys);

        // Create OAuth2PermissionGrant for admin consent
        var oauth2Grant = new OAuth2PermissionGrant
        {
            ClientId = servicePrincipalId,
            ConsentType = "AllPrincipals",
            ResourceId = graphSp.Id,
            Scope = scopes
        };

        await graphClient.Oauth2PermissionGrants.PostAsync(oauth2Grant, cancellationToken: cancellationToken);
    }

    public async Task<(bool Success, string? ErrorMessage)> DeleteSafeguardAppAsync(
        string tenantId,
        string applicationObjectId,
        CancellationToken cancellationToken = default)
    {
        try
        {
            var credential = new InteractiveBrowserCredential(new InteractiveBrowserCredentialOptions
            {
                TenantId = tenantId == "common" ? null : tenantId,
                ClientId = "14d82eec-204b-4c2f-b7e8-296a70dab67e",
                RedirectUri = new Uri("http://localhost")
            });

            var graphClient = new GraphServiceClient(credential, new[] { "Application.ReadWrite.All" });

            await graphClient.Applications[applicationObjectId].DeleteAsync(cancellationToken: cancellationToken);
            
            return (true, null);
        }
        catch (ServiceException)
        {
            return (false, "Failed to delete application. Please check your permissions.");
        }
        catch
        {
            return (false, "An unexpected error occurred while deleting the application.");
        }
    }
}

public class AppProvisioningResult
{
    public bool Success { get; set; }
    public string ClientId { get; set; } = string.Empty;
    public string ApplicationObjectId { get; set; } = string.Empty;
    public string? ServicePrincipalId { get; set; }
    public string DisplayName { get; set; } = string.Empty;
    public bool AlreadyExisted { get; set; }
    public string? ErrorMessage { get; set; }
}
