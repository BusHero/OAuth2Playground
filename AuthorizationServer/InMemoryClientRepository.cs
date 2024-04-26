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
}