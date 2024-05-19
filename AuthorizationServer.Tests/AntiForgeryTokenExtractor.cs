using AngleSharp.Html.Parser;
using Microsoft.Net.Http.Headers;

namespace AuthorizationServer.Tests;

public static class AntiForgeryTokenExtractor
{
    private const string AntiForgeryFieldName = "AntiForgeryTokenField";

    private const string AntiForgeryCookieName = "AntiForgeryTokenCookie";
    
    public static async Task<AntiForgeryTokenResponse> ExtractAntiForgeryValues(
        HttpResponseMessage response)
    {
        var cookie = ExtractAntiForgeryCookieValueFrom(response);
        var token = await ExtractAntiForgeryToken(await response.Content.ReadAsStringAsync());

        return new AntiForgeryTokenResponse
        {
            FormFieldName = AntiForgeryFieldName,
            FormFieldValue = token,
            CookieName = AntiForgeryCookieName,
            CookieValue = cookie,
        };
    }


    private static string ExtractAntiForgeryCookieValueFrom(HttpResponseMessage response)
    {
        var antiForgeryCookie = response.Headers.GetValues("Set-Cookie")
            .FirstOrDefault(x => x.Contains(AntiForgeryCookieName));

        if (antiForgeryCookie is null)
            throw new ArgumentException($"Cookie '{AntiForgeryCookieName}' not found in HTTP response",
                nameof(response));

        var antiForgeryCookieValue = SetCookieHeaderValue.Parse(antiForgeryCookie).Value.ToString();

        return antiForgeryCookieValue;
    }

    private static async Task<string> ExtractAntiForgeryToken(string htmlBody)
    {
        var parser = new HtmlParser();
        var document = await parser.ParseDocumentAsync(htmlBody);
        var item = document.QuerySelector($"""input[type="hidden"][name="{AntiForgeryFieldName}"]""");

        if (item is null)
        {
            throw new ArgumentException($"Anti forgery token '{AntiForgeryFieldName}' not found in HTML",
                nameof(htmlBody));
        }

        var value = item.GetAttribute("value");
        if (value is null)
        {
            throw new ArgumentException($"Anti forgery token '{AntiForgeryFieldName}' not found in HTML",
                nameof(htmlBody));
        }

        return value;
    }
}