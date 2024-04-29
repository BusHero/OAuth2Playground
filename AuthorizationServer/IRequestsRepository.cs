namespace AuthorizationServer;

public interface IRequestsRepository
{
    void Add(
        string requestId,
        string clientId,
        Uri redirectUri);

    RequestDto? GetRequest(string requestId);
}

public record RequestDto(
    string ClientId, 
    Uri RedirectUri);