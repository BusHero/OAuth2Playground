namespace AuthorizationServer;

internal sealed class InMemoryCodeRepository
{
    private readonly Dictionary<string, string> _codes = [];

    public void Add(string code, string clientId)
    {
        _codes[code] = clientId;
    }

    public string? GetAndRemoveClientForCode(string code)
    {
        _codes.Remove(code, out var clientId);

        return clientId;
    }
}