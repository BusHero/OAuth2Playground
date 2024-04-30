namespace AuthorizationServer;

public interface IRequestsRepository
{
    void Add(string requestId,
        string clientId,
        Uri redirectUri, 
        string responseType,
        string? state);

    RequestDto? GetRequest(string requestId);
}

public record RequestDto(
    string ClientId,
    Uri RedirectUri,
    string ResponseType,
    string State);