namespace AuthServer.Client.Abstractions;

public interface ITokenClient
{
    Task<TokenResponse> PostClientCredentials(TokenRequest request, CancellationToken cancellationToken);
    Task<TokenResponse> PostAuthorizationCode(TokenRequest request, CancellationToken cancellationToken);
    Task<TokenResponse> PostRefreshToken(TokenRequest request, CancellationToken cancellationToken);
}