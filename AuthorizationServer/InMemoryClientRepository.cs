namespace AuthorizationServer;

public class InMemoryClientRepository : IClientRepository
{
    private readonly List<Client> _clients = [];

    public Client? FindClientById(string clientId)
    {
        return _clients.FirstOrDefault(x => x.ClientId == clientId);
    }

    public void AddClient(Client client)
    {
        _clients.Add(client);
    }

    public void AddClient(
        string clientId,
        string clientSecret,
        params Uri[] redirectUris)
    {
        _clients.Add(new Client
        {
            ClientId = clientId,
            ClientSecret = clientSecret,
            RedirectUris = redirectUris,
        });
    }
}