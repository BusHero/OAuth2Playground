using System.Net.Http.Headers;
using System.Net.Http.Json;
using AutoFixture.Xunit2;
using Microsoft.AspNetCore.Mvc.Testing;

namespace WebResourceTests;

public class UnitTest1(WebApplicationFactory<Program> factory) 
    : IClassFixture<WebApplicationFactory<Program>>
{
    private readonly HttpClient _client = factory.CreateDefaultClient();

    [Theory, AutoData]
    public async Task RightAuthorizationSchemeReturnsToken(string token)
    {
        _client.DefaultRequestHeaders.Authorization
            = new AuthenticationHeaderValue("Bearer", token);
        
        var result = await _client
            .PostAsync("/resource", null) ;
        
        var content = await result.Content.ReadFromJsonAsync<Content>();
        
        content!
            .Message
            .Should()
            .Be(token);
    }

    [Fact]
    public async Task NoAuthHeaderReturnsNull()
    {
        var result = await _client
            .PostAsync("/resource", null) ;
        
        var content = await result.Content.ReadFromJsonAsync<Content>();
        
        content!
            .Message
            .Should()
            .BeNull();
    }

    [Theory, AutoData]
    public async Task InvalidAuthReturnsNull(string scheme, string token)
    {
        _client.DefaultRequestHeaders.Authorization
            = new AuthenticationHeaderValue(scheme, null);
        
        var result = await _client
            .PostAsync("/resource", null) ;
        
        var content = await result.Content.ReadFromJsonAsync<Content>();
        
        content!
            .Message
            .Should()
            .BeNull();
    }

    [Theory, AutoData]
    public async Task WrongAuthSchemeReturnsNull(string scheme, string token)
    {
        _client.DefaultRequestHeaders.Authorization
            = new AuthenticationHeaderValue(scheme, token);
        
        var result = await _client
            .PostAsync("/resource", null) ;
        
        var content = await result.Content.ReadFromJsonAsync<Content>();
        
        content!
            .Message
            .Should()
            .BeNull();
    }
    
    [Theory, AutoData]
    public async Task GetTokenFromBody(string token)
    {
        var result = await _client
            .PostAsync("/resource", new FormUrlEncodedContent([
                new KeyValuePair<string, string>("access_token", token)
            ])) ;

        var body = await result.Content.ReadAsStringAsync();
        var content = await result.Content.ReadFromJsonAsync<Content>();
        
        content!
            .Message
            .Should()
            .Be(token);
    }
    
    [Theory, AutoData]
    public async Task NoTokenInBodyReturnsNull(string otherName, string token)
    {
        var result = await _client
            .PostAsync("/resource", new FormUrlEncodedContent([
                new KeyValuePair<string, string>(otherName, token)
            ])) ;

        var body = await result.Content.ReadAsStringAsync();
        var content = await result.Content.ReadFromJsonAsync<Content>();
        
        content!
            .Message
            .Should()
            .BeNull();
    }
    
    [Theory, AutoData]
    public async Task GetTokenFromQueryParameters(string token)
    {
        var result = await _client
            .PostAsync($"/resource?access_token={token}", null) ;

        var body = await result.Content.ReadAsStringAsync();
        var content = await result.Content.ReadFromJsonAsync<Content>();
        
        content!
            .Message
            .Should()
            .Be(token);
    }
}

internal class Content
{
    public string Message { get; set; }
}
