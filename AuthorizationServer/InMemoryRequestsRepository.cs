﻿namespace AuthorizationServer;

public class InMemoryRequestsRepository : IRequestsRepository
{
    public void Clear()
    {
        _requests.Clear();
    }

    private readonly Dictionary<string, RequestDto> _requests = new();

    public IReadOnlyDictionary<string, RequestDto> Requests => _requests.AsReadOnly();

    public void Add(
        string requestId,
        string clientId,
        Uri redirectUri,
        string responseType,
        string state)
    {
        _requests[requestId] = new RequestDto(
            clientId,
            redirectUri,
            responseType,
            state);
    }

    public RequestDto? GetRequest(string requestId)
    {
        _requests.TryGetValue(requestId, out var query);
        return query;
    }
}