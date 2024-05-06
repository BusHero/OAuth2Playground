using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using JWT;
using JWT.Algorithms;
using JWT.Serializers;

namespace WebResourceTests;

public sealed class JwtTokenTests
{
    [Fact]
    public void Test()
    {
        var payload = new Dictionary<string, object>
        {
            { "claim1", 0 },
            { "claim2", "claim2-value" },
        };
        const string key = "secret";
        var token1 = GetCredibleTokenImplementation(
            payload,
            key);

        var token2 = GetMyImplementation(
            payload, key);

        token2
            .Should()
            .BeEquivalentTo(token1);
    }

    static string GetMyImplementation(
        Dictionary<string, object> payload,
        string secret)
    {
        var payloadAsJson = JsonSerializer.Serialize(payload);
        var headerAsJson = JsonSerializer.Serialize(new
        {
            typ = "JWT",
            alg = "HS256",
        });

        var headerBase64 = Convert.ToBase64String(Encoding.ASCII.GetBytes(headerAsJson));
        var payloadBase64 = Convert.ToBase64String(Encoding.ASCII.GetBytes(payloadAsJson));
        var dataToSign = $"{headerBase64}.{payloadBase64}";

        var encryptedData = HMACSHA256
            .HashData(
                Encoding.ASCII.GetBytes(secret),
                Encoding.ASCII.GetBytes(dataToSign));

        var signature = Convert.ToBase64String(encryptedData).Replace("/", "_").Replace("=", "");

        return $"{headerBase64}.{payloadBase64}.{signature}";
    }

    private string GetCredibleTokenImplementation(
        Dictionary<string, object> payload,
        string key)
    {
        IJwtAlgorithm algorithm = new HMACSHA256Algorithm();
        IJsonSerializer serializer = new JsonNetSerializer();
        IBase64UrlEncoder urlEncoder = new JwtBase64UrlEncoder();
        IJwtEncoder encoder = new JwtEncoder(algorithm, serializer, urlEncoder);

        var token = encoder.Encode(payload, key);

        return token;
    }
}