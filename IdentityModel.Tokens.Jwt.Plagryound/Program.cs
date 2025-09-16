using System.Buffers.Text;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using JWT;
using JWT.Algorithms;
using JWT.Serializers;

var payload = new Dictionary<string, object>
{
    ["iss"] = "https,//localhost,5001",
    ["nbf"] = 1757687619,
    ["iat"] = 1757687619,
    ["exp"] = 1757691219,
    ["aud"] = new[]
    {
        "resource1",
        "https,//localhost,5001/resources"
    },
    ["scope"] = new[]
    {
        "scope2"
    },
    ["client_id"] = "client.credentials.sample",
    ["jti"] = "0E4BF1D0E44F8BE9A7C7E34D3B39A5C2"
};

Console.WriteLine(GetCredibleTokenImplementation(payload, "secret"));
Console.WriteLine(GetMyImplementation(payload, "secret"));

return;

string GetMyImplementation(
    Dictionary<string, object> payload2,
    string secret)
{
    var payloadAsJson = JsonSerializer.Serialize(payload2);
    var headerAsJson = JsonSerializer.Serialize(new
    {
        typ = "JWT",
        alg = "HS256",
    });

    //Base64Url.EncodeToString
    var headerBase64 = Base64Url.EncodeToString(Encoding.ASCII.GetBytes(headerAsJson));
        //.Replace("/", "_", StringComparison.InvariantCulture)
        //.Replace("=", "", StringComparison.InvariantCulture);
    ;
    var payloadBase64 = Base64Url.EncodeToString(Encoding.ASCII.GetBytes(payloadAsJson));
        //.Replace("/", "_", StringComparison.InvariantCulture)
        //.Replace("=", "", StringComparison.InvariantCulture);
    ;
    var dataToSign = $"{headerBase64}.{payloadBase64}";

    var encryptedData = HMACSHA256
        .HashData(
            Encoding.ASCII.GetBytes(secret),
            Encoding.ASCII.GetBytes(dataToSign));

    var signature = Base64Url.EncodeToString(encryptedData);
        //.Replace("-", "+", StringComparison.InvariantCulture)
        //.Replace("/", "_", StringComparison.InvariantCulture)
        //.Replace("=", "", StringComparison.InvariantCulture);

    return $"{headerBase64}.{payloadBase64}.{signature}";
}

string GetCredibleTokenImplementation(
    Dictionary<string, object> payload2,
    string key)
{
    IJwtAlgorithm algorithm = new HMACSHA256Algorithm();
    IJsonSerializer serializer = new JsonNetSerializer();
    IBase64UrlEncoder urlEncoder = new JwtBase64UrlEncoder();
    IJwtEncoder encoder = new JwtEncoder(algorithm, serializer, urlEncoder);

    var token = encoder.Encode(payload2, key);

    return token;
}