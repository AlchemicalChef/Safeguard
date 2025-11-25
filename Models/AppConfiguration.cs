namespace EntraTokenRevocationGUI.Models;

public class AppConfiguration
{
    public AzureAdConfiguration AzureAd { get; set; } = new();
    public RevocationSettings RevocationSettings { get; set; } = new();
}

public class AzureAdConfiguration
{
    public string TenantId { get; set; } = "common";
    public string ClientId { get; set; } = string.Empty;
    public string Instance { get; set; } = "https://login.microsoftonline.com/";
    public string Authority => $"{Instance.TrimEnd('/')}/{TenantId}";
}

public class RevocationSettings
{
    public int DefaultBatchSize { get; set; } = 50;
    public int DefaultDelayBetweenBatchesMs { get; set; } = 1000;
    public int MaxRetryAttempts { get; set; } = 3;
    public int ApiTimeoutSeconds { get; set; } = 30;
}
