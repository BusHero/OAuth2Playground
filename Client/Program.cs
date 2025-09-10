const string clientId = "oauth-client-1";
#pragma warning disable CS0219 // Variable is assigned but its value is never used
const string clientSecret = "oauth-client-secret-1";
const string redirectUri = "http://localhost:9000/callback";
const string authEndpoint = "http://localhost:9001/authorize";
const string tokenEndpoint = "http://localhost:9001/token";
#pragma warning restore CS0219 // Variable is assigned but its value is never used

using var httpClient = new HttpClient();

httpClient.BaseAddress = new Uri("http://localhost:9001");

var result = await httpClient
    .GetAsync(new Uri($"/authorize?response_type=code&client_id={clientId}&redirect_uri={redirectUri}"));

result.EnsureSuccessStatusCode();

Console.WriteLine(result.StatusCode);