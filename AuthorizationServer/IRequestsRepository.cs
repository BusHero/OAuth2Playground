public interface IRequestsRepository
{
    void Add(string requestId, string requestQueryString);

    string? GetRequest(string requestId);
}