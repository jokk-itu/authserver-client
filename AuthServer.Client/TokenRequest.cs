namespace AuthServer.Client;

public class TokenRequest
{
    public required Uri Address { get; init; }
    public required string ClientId { get; init; }
    public string? ClientSecret { get; init; }
    public string? ClientAssertion { get; init; }
    public string? RefreshToken { get; init; }
    public string? Code { get; init; }
    public string? RedirectUri { get; init; }
    public string? CodeVerifier { get; init; }
    public IEnumerable<string> Scope { get; init; } = [];
    public IEnumerable<string> Resource { get; init; } = [];
    public IList<KeyValuePair<string, string>> AdditionalParameters { get; init; } = [];
}