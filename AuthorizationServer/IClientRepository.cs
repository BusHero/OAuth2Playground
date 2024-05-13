namespace AuthorizationServer;

public interface IClientRepository
{
    Client? FindClientById(string clientId);

    void AddClient(
        string clientId,
        string clientSecret,
        IReadOnlyCollection<string> scopes,
        params Uri[] redirectUris);
}