namespace AuthorizationServer;

internal sealed class InMemoryRequestsRepository
{
    private readonly Dictionary<string, RequestDto> _requests = new();

    public void Add(
        string requestId,
        string clientId,
        Uri redirectUri,
        string responseType,
        string? state) =>
        _requests[requestId] = new RequestDto(
            RedirectUri: redirectUri,
            ClientId: clientId,
            ResponseType: responseType,
            State: state);

    public RequestDto? GetAndRemoveRequest(string requestId)
    {
        _requests.Remove(requestId, out var query);
        return query;
    }
}

public sealed record RequestDto(
    Uri RedirectUri,
    string ClientId,
    string ResponseType,
    string? State);