using JWT;
using JWT.Algorithms;
using JWT.Serializers;
using Shouldly;
using System.Buffers.Text;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace AuthorizationServer.Tests.JwtTokens;

public sealed class JwtTokensTests
{
    private readonly Dictionary<string, object> payload = new()
    {
        ["iss"] = "https,//localhost,5001",
        ["nbf"] = 1757687619,
        ["iat"] = 1757687619,
        ["exp"] = 1757691219,
        ["aud"] = new[]
        {
            "resource1",
            "https,//localhost,5001/resources",
        },
        ["scope"] = new[]
        {
            "scope2",
        },
        ["client_id"] = "client.credentials.sample",
        ["jti"] = "0E4BF1D0E44F8BE9A7C7E34D3B39A5C2",
    };
    private const string SECRET = "secret";

    [Fact]
    public void HMACTest()
    {
        var credibleJwt = GetCredibleHmacJwt(payload, SECRET);
        var customJwt = GetCustomHmacJwt(payload, SECRET);

        customJwt.ShouldBe(credibleJwt);
    }

    [Fact]
    public void RSA256Test()
    {
        using var rsaKey = RSA.Create();
        var bytes = rsaKey.ExportSubjectPublicKeyInfo();
        var pem = new string(PemEncoding.Write("PUBLIC KEY", bytes));

        var credibleJwt = GetCredibleRSA256(payload, rsaKey, SECRET);
        //var customJwt = GetCustomHmacJwt(payload, SECRET);

        Assert.Multiple(
            () => pem.ShouldBeNull(),
            () => credibleJwt.ShouldBeNull());
    }

    private static string GetCredibleRSA256(
        Dictionary<string, object> payload,
        RSA rsaKey,
        string secret)
    {
        IJwtAlgorithm algorithm = new RS256Algorithm(rsaKey, rsaKey);
        IJsonSerializer serializer = new JsonNetSerializer();
        IBase64UrlEncoder urlEncoder = new JwtBase64UrlEncoder();
        IJwtEncoder encoder = new JwtEncoder(algorithm, serializer, urlEncoder);

        var token = encoder.Encode(payload, secret);

        return token;
    }

    private static string GetCredibleHmacJwt(
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

    private static string GetCustomHmacJwt(
        Dictionary<string, object> payload,
        string secret)
    {
        var payloadAsJson = JsonSerializer.Serialize(payload);
        var headerAsJson = JsonSerializer.Serialize(new
        {
            typ = "JWT",
            alg = "HS256",
        });

        var headerBase64 = Base64Url.EncodeToString(Encoding.ASCII.GetBytes(headerAsJson));
        var payloadBase64 = Base64Url.EncodeToString(Encoding.ASCII.GetBytes(payloadAsJson));
        var dataToSign = $"{headerBase64}.{payloadBase64}";

        var encryptedData = HMACSHA256
            .HashData(
                Encoding.ASCII.GetBytes(secret),
                Encoding.ASCII.GetBytes(dataToSign));

        var signature = Base64Url.EncodeToString(encryptedData);

        return $"{headerBase64}.{payloadBase64}.{signature}";
    }
}
