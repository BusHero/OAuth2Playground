namespace AuthorizationServer;

public class InMemoryRequestsRepository : IRequestsRepository
{
    public void Clear()
    {
        _requests.Clear();
    }

    private readonly Dictionary<string, string> _requests = new();

    public IReadOnlyDictionary<string, string> Requests => _requests.AsReadOnly();

    public void Add(string requestId, string requestQueryString)
    {
        _requests[requestId] = requestQueryString;
    }

    public string? GetRequest(string requestId)
    {
        _requests.TryGetValue(requestId, out var query);
        return query;
    }
}