using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;

namespace CertificateChainPinning
{
    internal class PinCertificateChain
    {
        private readonly string _domain;

        private PinCertificateChain(string targetDomain)
        {
            _domain = targetDomain;
        }

        // ReSharper disable once UnusedParameter.Global
        public static void Main(string[] _)
        {
            new PinCertificateChain("urip.com").ValidateDomain();
            new PinCertificateChain("cert.ist").ValidateDomain();
            new PinCertificateChain("asciirange.com").ValidateDomain();
            new PinCertificateChain("tilltrump.com").ValidateDomain();
            new PinCertificateChain("jbird.dev").ValidateDomain();
        }

        private List<string> GetSha1ThumbprintFromApi()
        {
            ServicePointManager.ServerCertificateValidationCallback = null;
            var requestUriString = $"https://api.cert.ist/{_domain}";
            WebRequest request = WebRequest.Create(requestUriString);
            HttpWebResponse response = (HttpWebResponse) request.GetResponse();
            StreamReader reader = new StreamReader(response.GetResponseStream()!);
            CertIstApi certIstApi = JsonSerializer.Deserialize<CertIstApi>(reader.ReadToEnd());
            List<String> all = new List<string>(certIstApi.Chain.Length);
            all.AddRange(certIstApi.Chain.Select(link => link.Der.Hashes.Sha1));
            return all;
        }

        private void ValidateDomain()
        {
            try
            {
                WebRequest.DefaultWebProxy = null;
                ServicePointManager.ServerCertificateValidationCallback = PinPublicKey;
                WebRequest wr = WebRequest.Create($"https://{_domain}");
                wr.GetResponse();
            }
            catch (WebException)
            {
                Environment.Exit(1);
            }
        }

        private bool PinPublicKey(object sender, X509Certificate certificate, X509Chain chain,
            SslPolicyErrors sslPolicyErrors)
        {
            var keyDerFromApis = GetSha1ThumbprintFromApi();

            int i = 0;
            foreach (var element in chain.ChainElements)
            {
                i++;
                var value = Sha1(element.Certificate.RawData);
                if (!keyDerFromApis.Contains(value))
                {
                    // TODO: So what's going on here? this works but why is amazon's root not correct
                    if (chain.ChainElements.Count != keyDerFromApis.Count && i == chain.ChainElements.Count)
                    {
                        continue;
                    }

                    Console.WriteLine($"{i} of {chain.ChainElements.Count}; missing val: {value}");
                    Console.WriteLine(element.Certificate.GetNameInfo(X509NameType.SimpleName, false));
                    return false;
                }
            }

            Console.WriteLine($"{_domain} locally observed certificate chain sha1 hashes from api matched");
            return true;
        }

        private static string Sha1(byte[] val)
        {
            var crypt = new SHA1Managed();
            var hash = new StringBuilder();
            byte[] crypto = crypt.ComputeHash(val);
            foreach (byte theByte in crypto)
            {
                hash.Append(theByte.ToString("x2"));
            }

            return hash.ToString();
        }
    }
}