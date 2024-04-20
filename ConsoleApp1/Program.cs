using System.Security.Cryptography;
using System.Text;

while (true)
{
    var line = Console.ReadLine();

    var sha256 = GetSha256(line!);
    var sha1 = GetSha1(line!);
    var hmac1 = GetHmac256(line!, "secret");
    var hmac2 = GetHmac256(line!, "secret1");

    Console.WriteLine(sha256);
    Console.WriteLine(sha1);
    Console.WriteLine(hmac1);
    Console.WriteLine(hmac2);
}

string GetHmac256(string input, string secret)
{
    var encryptedData = HMACSHA256
        .HashData(
            Encoding.ASCII.GetBytes(secret),
            Encoding.ASCII.GetBytes(input));
    
    var output = BitConverter
        .ToString(encryptedData)
        .Replace("-", "");
    
    return output;
}

string GetSha1(string input)
{
    var bytes = Encoding.ASCII.GetBytes(input);
    var result = SHA1.HashData(bytes);
    var output = BitConverter.ToString(result).Replace("-", "");
    return output;
}

string GetSha256(string input)
{
    var bytes = Encoding.ASCII.GetBytes(input);
    var result = SHA256.HashData(bytes);
    var output = BitConverter.ToString(result).Replace("-", "");
    return output;
}