const string clientId = "oauth-client-1";
const string clientSecret = "oauth-client-secret-1";
const string redirectUri = "http://localhost:9000/callback";
const string authEndpoint = "http://localhost:9001/authorize";
const string tokenEndpoint = "http://localhost:9001/token";

using var httpClient = new HttpClient();

httpClient.BaseAddress = new Uri("http://localhost:9001");

var result = await httpClient
    .GetAsync($"/authorize?response_type=code&client_id={clientId}&redirect_uri={redirectUri}");

result.EnsureSuccessStatusCode();

Console.WriteLine(result.StatusCode);