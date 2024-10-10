using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Web;
using AuthServer.Client.Abstractions;

namespace AuthServer.Client;

internal class TokenClient : ITokenClient
{
    private const string ClientAssertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

    private readonly HttpClient _httpClient;

    public TokenClient(IHttpClientFactory httpClientFactory)
    {
        _httpClient = httpClientFactory.CreateClient(HttpClientNameConstants.TokenClient);
    }

    public async Task<TokenResponse> PostClientCredentials(TokenRequest request, CancellationToken cancellationToken)
    {
        var httpRequest = new HttpRequestMessage(HttpMethod.Post, request.Address);
        var content = new List<KeyValuePair<string, string>>
        {
            new("grant_type", "client_credentials")
        };

        AddResource(request.Resource, content);
        AddScope(request.Scope, content);
        AddAdditionalParameters(request.AdditionalParameters, content);
        AddClientAuthentication(request, httpRequest.Headers, content);

        httpRequest.Content = new FormUrlEncodedContent(content);
        var httpResponse = await _httpClient.SendAsync(httpRequest, cancellationToken);
        httpResponse.EnsureSuccessStatusCode();

        var responseContent = await httpResponse.Content.ReadAsStringAsync(cancellationToken);
        var deserializedResponseContent = JsonSerializer.Deserialize<TokenResponse>(responseContent);
        if (deserializedResponseContent is null)
        {
            throw new JsonException($"response could not be deserialized to {nameof(TokenResponse)}");
        }

        return deserializedResponseContent;
    }

    public async Task<TokenResponse> PostAuthorizationCode(TokenRequest request, CancellationToken cancellationToken)
    {
        var httpRequest = new HttpRequestMessage(HttpMethod.Post, request.Address);
        var content = new List<KeyValuePair<string, string>>
        {
            new("grant_type", "authorization_code"),
            new("code", request.Code ?? throw new ArgumentException(nameof(request.Code))),
            new("code_verifier", request.CodeVerifier ?? throw new ArgumentException(nameof(request.CodeVerifier)))
        };

        if (request.RedirectUri is not null)
        {
            content.Add(new KeyValuePair<string, string>("redirect_uri", request.RedirectUri));
        }

        AddResource(request.Resource, content);
        AddAdditionalParameters(request.AdditionalParameters, content);
        AddClientAuthentication(request, httpRequest.Headers, content);

        httpRequest.Content = new FormUrlEncodedContent(content);
        var httpResponse = await _httpClient.SendAsync(httpRequest, cancellationToken);
        httpResponse.EnsureSuccessStatusCode();

        var responseContent = await httpResponse.Content.ReadAsStringAsync(cancellationToken);
        var deserializedResponseContent = JsonSerializer.Deserialize<TokenResponse>(responseContent);
        if (deserializedResponseContent is null)
        {
            throw new JsonException($"response could not be deserialized to {nameof(TokenResponse)}");
        }

        return deserializedResponseContent;
    }

    public async Task<TokenResponse> PostRefreshToken(TokenRequest request, CancellationToken cancellationToken)
    {
        var httpRequest = new HttpRequestMessage(HttpMethod.Post, request.Address);
        var content = new List<KeyValuePair<string, string>>
        {
            new("grant_type", "refresh_token"),
            new("refresh_token", request.RefreshToken ?? throw new ArgumentException(nameof(request.RefreshToken))),
        };

        AddScope(request.Scope, content);
        AddResource(request.Resource, content);
        AddAdditionalParameters(request.AdditionalParameters, content);
        AddClientAuthentication(request, httpRequest.Headers, content);

        httpRequest.Content = new FormUrlEncodedContent(content);
        var httpResponse = await _httpClient.SendAsync(httpRequest, cancellationToken);
        httpResponse.EnsureSuccessStatusCode();

        var responseContent = await httpResponse.Content.ReadAsStringAsync(cancellationToken);
        var deserializedResponseContent = JsonSerializer.Deserialize<TokenResponse>(responseContent);
        if (deserializedResponseContent is null)
        {
            throw new JsonException($"response could not be deserialized to {nameof(TokenResponse)}");
        }

        return deserializedResponseContent;
    }

    private static void AddScope(IEnumerable<string> scope, List<KeyValuePair<string, string>> content)
    {
        var splitScope = string.Join(' ', scope);
        if (!string.IsNullOrEmpty(splitScope))
        {
            content.Add(new KeyValuePair<string, string>("scope", splitScope));
        }
    }

    private static void AddResource(IEnumerable<string> resource, List<KeyValuePair<string, string>> content)
    {
        content.AddRange(resource.Select(x => new KeyValuePair<string, string>("resource", x)));
    }

    private static void AddAdditionalParameters(IList<KeyValuePair<string, string>> additionalParameters, List<KeyValuePair<string, string>> content)
    {
        content.AddRange(additionalParameters.Select(x => new KeyValuePair<string, string>(x.Key, x.Value)));
    }

    private static void AddClientAuthentication(TokenRequest tokenRequest, HttpRequestHeaders httpRequestHeaders,
        List<KeyValuePair<string, string>> content)
    {
        if (tokenRequest.ClientSecret is not null)
        {
            var encodedClientId = HttpUtility.UrlEncode(tokenRequest.ClientId);
            var encodedClientSecret = HttpUtility.UrlEncode(tokenRequest.ClientSecret);
            var headerValue = $"{encodedClientId}:{encodedClientSecret}";
            var convertedHeaderValue = Convert.ToBase64String(Encoding.UTF8.GetBytes(headerValue));
            httpRequestHeaders.Authorization = new AuthenticationHeaderValue("Basic", convertedHeaderValue);
        }
        else if (tokenRequest.ClientAssertion is not null)
        {
            content.Add(new KeyValuePair<string, string>("client_id", tokenRequest.ClientId));
            content.Add(new KeyValuePair<string, string>("client_assertion", tokenRequest.ClientAssertion));
            content.Add(new KeyValuePair<string, string>("client_assertion_type", ClientAssertionType));
        }
        else
        {
            content.Add(new KeyValuePair<string, string>("client_id", tokenRequest.ClientId));
        }
    }
}