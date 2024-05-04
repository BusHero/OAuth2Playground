namespace WebApplication2;

internal sealed class TokenExtractor(ILogger<TokenExtractor> logger)
{
    public async Task<string?> GetBearerToken(HttpContext context)
    {
        return context.Request switch
        {
            { Headers.Authorization: [{ } x] } => x.Split(' ') switch
            {
                ["Bearer", var token] => token,
                _ => null
            },
            { HasFormContentType: true } x => await x.ReadFormAsync() switch
            {
                var form when form.TryGetValue("access_token", out var accessToken) => accessToken.ToString(),
                _ => null,
            },
            { Query: var query } when query.TryGetValue("access_token", out var accessToken) => accessToken.ToString(),
            _ => null,
        };
    }
}