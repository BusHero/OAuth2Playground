namespace AuthorizationServer;

public interface IRequestsRepository
{
    void Add(string requestId,
        Uri redirectUri, 
        string responseType,
        string? state);

    RequestDto? GetAndRemoveRequest(string requestId);
}

public record RequestDto(
    Uri RedirectUri,
    string ResponseType,
    string? State);