namespace AuthorizationServer;

public class InMemoryRequestsRepository : IRequestsRepository
{
    private readonly Dictionary<string, RequestDto> _requests = new();

    public void Add(
        string requestId,
        Uri redirectUri,
        string responseType,
        string? state)
    {
        _requests[requestId] = new RequestDto(
            redirectUri,
            responseType,
            state);
    }

    public RequestDto? GetAndRemoveRequest(string requestId)
    {
        _requests.Remove(requestId, out var query);
        return query;
    }
}