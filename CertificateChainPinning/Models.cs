// ReSharper disable UnusedAutoPropertyAccessor.Global
// ReSharper disable ClassNeverInstantiated.Global

using System.Text.Json.Serialization;

namespace CertificateChainPinning
{
    public class CertIstApiHashes
    {
        [JsonPropertyName("sha1")] public string Sha1 { get; set; }
    }

    public class CertIstApiKeyStats
    {
        [JsonPropertyName("hashes")] public CertIstApiHashes Hashes { get; set; }
    }

    public class Chain
    {
        [JsonPropertyName("der")] public CertIstApiKeyStats Der { get; set; }
    }

    public class CertIstApi
    {
        [JsonPropertyName("chain")] public Chain[] Chain { get; set; }
    }
}