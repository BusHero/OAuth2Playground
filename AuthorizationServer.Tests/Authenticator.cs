using Flurl.Http;

namespace AuthorizationServer.Tests;

internal sealed class Authenticator(
    HttpClient oauthClient, 
    InMemoryClientRepository clientRepository)
{
    private readonly FlurlClient _authClient = new(oauthClient);

    public async Task<string> PerformAuthentication(
        Client client)
    {
        clientRepository.AddClient(client);

        var requestId = await GetRequestId(
            client.ClientId,
            client.RedirectUris[0]);

        var authorizationCode = await GetAuthorizationCode(
            requestId);

        var token = await GetToken(
            client.ClientId,
            client.ClientSecret,
            authorizationCode);

        return token;
    }
    
    private async Task<string> GetRequestId(
        string clientId,
        Uri redirectUri)
    {
        var response = await _authClient
            .Request()
            .WithAutoRedirect(false)
            .AppendPathSegment("authorize")
            .AppendQueryParam("response_type", "code")
            .AppendQueryParam("redirect_uri", redirectUri.ToString())
            .AppendQueryParam("state", Guid.NewGuid().ToString())
            .AppendQueryParam("client_id", clientId)
            .GetAsync();

        var responseObject = await response
            .GetJsonAsync<Response>();

        return responseObject.Code;
    }

    private async Task<string> GetAuthorizationCode(
        string requestId)
    {
        var result = await _authClient
            .Request()
            .AllowAnyHttpStatus()
            .WithAutoRedirect(false)
            .AppendPathSegment("approve")
            .PostUrlEncodedAsync(new Dictionary<string, string>
            {
                ["reqId"] = requestId,
                ["approve"] = "approve",
            });

        var query = result
            .ResponseMessage
            .Headers
            .Location!
            .GetQueryParameters();

        return query["code"];
    }

    private async Task<string> GetToken(
        string clientId,
        string clientSecret,
        string authorizationCode)
    {
        var response = await _authClient
            .Request()
            .AllowAnyHttpStatus()
            .AppendPathSegment("token")
            .WithBasicAuth(clientId, clientSecret)
            .PostUrlEncodedAsync(new Dictionary<string, string>
            {
                ["grant_type"] = "authorization_code",
                ["code"] = authorizationCode,
            });

        var json = await response.GetJsonAsync<Dictionary<string, string>>();

        return json["access_token"];
    }
}