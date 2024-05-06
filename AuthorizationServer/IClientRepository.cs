namespace AuthorizationServer;

public interface IClientRepository
{
    Client? FindClientById(string clientId);
}