using System.Net.Http.Headers;
using System.Text.Json.Serialization;
using Flurl.Http;

namespace AuthorizationServer.Tests;

internal sealed class Authenticator(
    HttpClient oauthClient)
{
    private readonly FlurlClient _authClient = new(oauthClient);

    public async Task<string> PerformAuthentication(
        Uri redirectUri)
    {
        var client = await RegisterClient(RegisterRequest.Valid with
        {
            RedirectUris = [redirectUri]
        });

        var requestId = await GetRequestId(
            client.ClientId,
            redirectUri,
            Guid.NewGuid().ToString());

        var authorizationCode = await GetAuthorizationCode(
            requestId);

        var token = await GetToken(
            client.ClientId,
            client.ClientSecret,
            authorizationCode);

        return token;
    }

    public async Task<string> GetRequestId(
        string clientId,
        Uri redirectUri,
        string state,
        string responseType = "code")
    {
        var response = await PerformAuthorizationRequest(
            clientId: clientId,
            redirectUri: redirectUri,
            state: state,
            scope: default(string),
            responseType: responseType);

        var responseObject = await response
            .GetJsonAsync<Response>();

        return responseObject.Code;
    }

    public async Task<IFlurlResponse> PerformAuthorizationRequest(
        string? clientId = null,
        Uri? redirectUri = null,
        string? state = null,
        string? responseType = "code")
    {
        return await PerformAuthorizationRequest(
            clientId,
            redirectUri,
            state,
            Array.Empty<string>(),
            responseType);
    }

    public async Task<IFlurlResponse> PerformAuthorizationRequest(
        string? clientId = null,
        Uri? redirectUri = null,
        string? state = null,
        string? scope = null,
        string? responseType = "code")
    {
        return await PerformAuthorizationRequest(
            clientId,
            redirectUri,
            state,
            scope is null ? null : [scope],
            responseType);
    }

    public async Task<IFlurlResponse> PerformAuthorizationRequest(
        string? clientId = null,
        Uri? redirectUri = null,
        string? state = null,
        IReadOnlyCollection<string>? scope = null,
        string? responseType = "code")
    {
        var request = _authClient
            .Request()
            .AllowAnyHttpStatus()
            .WithAutoRedirect(false)
            .AppendPathSegment("authorize");

        if (clientId is not null)
        {
            request = request
                .AppendQueryParam("client_id", clientId);
        }

        if (redirectUri is not null)
        {
            request = request
                .AppendQueryParam("redirect_uri", redirectUri.ToString());
        }

        if (responseType is not null)
        {
            request = request
                .AppendQueryParam("response_type", responseType);
        }

        if (state is not null)
        {
            request = request
                .AppendQueryParam("state", state);
        }

        if (scope is { Count: > 0 })
        {
            var scopeData = string.Join(' ', scope);
            request = request.AppendQueryParam("scope", scopeData);
        }

        var response = await request
            .GetAsync();

        return response;
    }

    public async Task<IFlurlResponse> PerformApproveRequest(
        string requestId,
        string approve = "approve")
    {
        var result = await PerformApproveRequest(new Dictionary<string, string>
        {
            ["reqId"] = requestId,
            ["approve"] = "approve",
        });

        return result;
    }

    public async Task<IFlurlResponse> PerformApproveRequest(
        IReadOnlyDictionary<string, string> data)
    {
        var result = await _authClient
            .Request()
            .AllowAnyHttpStatus()
            .WithAutoRedirect(false)
            .AppendPathSegment("approve")
            .PostUrlEncodedAsync(data);

        return result;
    }

    public async Task<string> GetAuthorizationCode(
        string clientId,
        Uri redirectUri,
        string state)
    {
        var requestId = await GetRequestId(
            clientId,
            redirectUri,
            state);

        var result = await PerformApproveRequest(
            requestId);

        var query = result
            .ResponseMessage
            .Headers
            .Location!
            .GetQueryParameters();

        return query["code"];
    }

    public async Task<string> GetAuthorizationCode(
        string requestId)
    {
        var result = await PerformApproveRequest(
            requestId);

        var query = result
            .ResponseMessage
            .Headers
            .Location!
            .GetQueryParameters();

        return query["code"];
    }

    public async Task<string> GetToken(
        string clientId,
        string clientSecret,
        string authorizationCode)
    {
        var response = await PerformTokenRequest(
            clientId,
            clientSecret,
            authorizationCode);

        var json = await response.GetJsonAsync<Dictionary<string, string>>();

        return json["access_token"];
    }

    public async Task<IFlurlResponse> PerformTokenRequest(
        string clientId,
        string clientSecret,
        string authorizationCode) =>
        await PerformTokenRequest(
            clientId,
            clientSecret,
            "authorization_code",
            authorizationCode);

    public async Task<IFlurlResponse> PerformTokenRequest(
        string clientId,
        string clientSecret,
        string grantType,
        string authorizationCode) =>
        await PerformTokenRequest(
            clientId,
            clientSecret,
            new Dictionary<string, string>
            {
                ["grant_type"] = grantType,
                ["code"] = authorizationCode,
            });

    public async Task<IFlurlResponse> PerformTokenRequest(
        string clientId,
        string clientSecret,
        IReadOnlyDictionary<string, string> data) =>
        await _authClient
            .Request()
            .AllowAnyHttpStatus()
            .AppendPathSegment("token")
            .WithBasicAuth(clientId, clientSecret)
            .PostUrlEncodedAsync(data);

    public async Task<IFlurlResponse> PerformTokenRequest(
        string authorizationCode) =>
        await PerformTokenRequest(new Dictionary<string, string>
        {
            ["grant_type"] = "authorization_code",
            ["code"] = authorizationCode,
        });

    public async Task<IFlurlResponse> PerformTokenRequest(
        Dictionary<string, string> data) =>
        await _authClient
            .Request()
            .AllowAnyHttpStatus()
            .AppendPathSegment("token")
            .PostUrlEncodedAsync(data);

    public async Task<IFlurlResponse> PerformTokenRequest(
        AuthenticationHeaderValue authenticationHeaderValue,
        string code) =>
        await _authClient
            .Request()
            .AllowAnyHttpStatus()
            .AppendPathSegment("token")
            .WithAuthorization(authenticationHeaderValue)
            .PostUrlEncodedAsync(new Dictionary<string, string>
            {
                ["grant_type"] = "authorization_code",
                ["code"] = code,
            });

    public async Task<RegisterResponse> RegisterClient(
        RegisterRequest request)
    {
        var response = await PerformRegisterRequest(request);

        var client = await response.GetJsonAsync<RegisterResponse>();

        return client;
    }

    public async Task<IFlurlResponse> PerformRegisterRequest(
        RegisterRequest request)
    {
        return await _authClient
            .Request()
            .AllowAnyHttpStatus()
            .AppendPathSegment("register")
            .PostJsonAsync(request);
    }
}

public sealed record RegisterRequest
{
    public static RegisterRequest Valid { get; } = new()
    {
        TokenEndpointAuthMethod = "secret_basic",
        GrantTypes = [],
        ResponseTypes = [],
        RedirectUris = [new Uri("http://example.com")],
        Scope = "foo",
    };

    [JsonPropertyName("token_endpoint_auth_method")]
    public string? TokenEndpointAuthMethod { get; init; }

    [JsonPropertyName("grant_types")] public required string[] GrantTypes { get; init; }

    [JsonPropertyName("response_types")] public required string[] ResponseTypes { get; init; }

    [JsonPropertyName("redirect_uris")] public required Uri[] RedirectUris { get; init; }

    [JsonPropertyName("scope")] public required string Scope { get; init; }
}