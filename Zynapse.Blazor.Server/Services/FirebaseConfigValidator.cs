using System.Text.Json;

namespace Zynapse.Blazor.Server.Services;

public static class FirebaseConfigValidator
{
    private static readonly string[] RequiredFields = { "type", "project_id", "private_key", "client_email" };

    public static void ValidateServiceAccountJson(string? configJson)
    {
        if (string.IsNullOrWhiteSpace(configJson))
        {
            throw new FirebaseConfigException(
                "Firebase configuration is missing",
                "Please follow these steps:\n" +
                "1. Copy appsettings.Development.json to create your appsettings.json\n" +
                "2. Go to Firebase Console → Project Settings → Service Accounts\n" +
                "3. Click 'Generate New Private Key' to download your service account JSON\n" +
                "4. Copy the JSON content into the Firebase:ServiceAccountJson section of appsettings.json"
            );
        }

        JsonElement config;
        try
        {
            config = JsonDocument.Parse(configJson).RootElement;
        }
        catch (JsonException)
        {
            throw new FirebaseConfigException(
                "Invalid JSON configuration",
                "The Firebase service account JSON is not valid. Please ensure you've copied the entire JSON content correctly."
            );
        }

        ValidateRequiredFields(config);
        ValidateServiceAccountType(config);
        ValidatePrivateKeyFormat(config);
    }

    private static void ValidateRequiredFields(JsonElement config)
    {
        var missingFields = RequiredFields
            .Where(field => !config.TryGetProperty(field, out var value) || string.IsNullOrWhiteSpace(value.GetString()))
            .ToList();

        if (missingFields.Any())
        {
            throw new FirebaseConfigException(
                "Firebase configuration is invalid",
                $"The following required fields are missing or empty:\n- {string.Join("\n- ", missingFields)}\n\n" +
                "Please ensure these fields are properly set in your Firebase:ServiceAccountJson configuration."
            );
        }
    }

    private static void ValidateServiceAccountType(JsonElement config)
    {
        if (config.GetProperty("type").GetString() != "service_account")
        {
            throw new FirebaseConfigException(
                "Invalid Firebase configuration",
                "The 'type' field must be 'service_account'.\n" +
                "Please make sure you're using a service account JSON file, not a regular Firebase configuration."
            );
        }
    }

    private static void ValidatePrivateKeyFormat(JsonElement config)
    {
        var privateKey = config.GetProperty("private_key").GetString();
        if (!privateKey!.StartsWith("-----BEGIN PRIVATE KEY-----") || !privateKey.EndsWith("-----END PRIVATE KEY-----\n"))
        {
            throw new FirebaseConfigException(
                "Invalid Firebase private key format",
                "The private key should start with '-----BEGIN PRIVATE KEY-----' and end with '-----END PRIVATE KEY-----\\n'\n" +
                "Please make sure you've copied the entire private key from your service account JSON file."
            );
        }
    }
} 