using System;
using System.Net.Http;
using System.Net.Http.Headers;
using Microsoft.Azure.WebJobs.Description;
using Microsoft.Azure.WebJobs.Host.Config;
using Newtonsoft.Json.Linq;

namespace KeyVaultSecretsBinding
{
    [Binding]
    [AttributeUsage(AttributeTargets.Parameter)]
    public class KeyVaultBindingAttribute : Attribute
    {
        public string secretUrl { get; set; }
    }

    public class KeyVaultItem
    {
        public string name { get; set; }
    }

    public class KeyVaultSecret : IExtensionConfigProvider
    {
        private static readonly HttpClient client = new HttpClient();

        public void Initialize(ExtensionConfigContext context)
        {
            context.AddConverter<KeyVaultItem, string>(ConvertToString);
            context.AddConverter<string, KeyVaultItem>(ConvertToKeyVaultItem);

            var rule = context.AddBindingRule<KeyVaultBindingAttribute>();
            rule.BindToInput<KeyVaultItem>(BuildItemFromAttr);
        }

        private string ConvertToString(KeyVaultItem item)
        {
            return item.name;
        }

        private KeyVaultItem ConvertToKeyVaultItem(string arg)
        {
            return new KeyVaultItem
            {
                name = arg

            };
        }

        // Slightly modified version of https://stackoverflow.com/questions/7578857/how-to-check-whether-a-string-is-a-valid-http-url
        private bool IsUri(String endpoint)
        {
            Uri uriResult;
            bool result = Uri.TryCreate(endpoint, UriKind.Absolute, out uriResult)
                && uriResult.Scheme == Uri.UriSchemeHttps;

            return result;
        }

        private KeyVaultItem BuildItemFromAttr(KeyVaultBindingAttribute attr)
        {
            // This environment variable may not be set locally so let's check
            // if it works
            var baseEndpoint = Environment.GetEnvironmentVariable("MSI_ENDPOINT");

            // TODO: When we add local fallbacks it probably goes here! 
            if (!IsUri(baseEndpoint))
            {
                throw new Exception("MSI Endpoint doesn't appear to be a valid HTTPS URL.");
            }

            var secret = Environment.GetEnvironmentVariable("MSI_SECRET");
            var endpoint = Environment.GetEnvironmentVariable("MSI_ENDPOINT") +
                                      "?resource=https://vault.azure.net" +
                                      "&api-version=2017-09-01";                

            var bearerTokenMessage = new HttpRequestMessage(HttpMethod.Get, endpoint);
            bearerTokenMessage.Headers.Add("secret", secret);

            HttpResponseMessage bearerTokenResponse = client.SendAsync(bearerTokenMessage).Result;

            if (!bearerTokenResponse.IsSuccessStatusCode)
            {
                throw new Exception("Invalid response from MSI Endpoint.");
            }

            // We need to read the result in a sync way in this method
            JToken bearerTokenDecodedResponse = JObject.Parse(bearerTokenResponse.Content.ReadAsStringAsync().Result);

            string bearerToken = (string) bearerTokenDecodedResponse["bearer_token"];

            var secretRequest = new HttpRequestMessage(HttpMethod.Get, attr.secretUrl + "?api-version=2016-10-01");
            secretRequest.Headers.Authorization = new AuthenticationHeaderValue("Bearer", bearerToken);

            HttpResponseMessage secretResponse = client.SendAsync(secretRequest).Result;

            if (!secretResponse.IsSuccessStatusCode)
            {
                throw new Exception("Invalid response from Vault Endpoint.");
            }

            // We need to read the result in a sync way in this method
            JToken secretDecodedResponse = JObject.Parse(secretResponse.Content.ReadAsStringAsync().Result);

            return new KeyVaultItem
            {
                name = (string) secretDecodedResponse["value"]
            };
        }
    }
}
