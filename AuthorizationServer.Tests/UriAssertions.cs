using FluentAssertions;
using FluentAssertions.Execution;
using FluentAssertions.Primitives;

namespace AuthorizationServer.Tests;

public sealed class UriAssertions(Uri? uri)
    : ReferenceTypeAssertions<Uri?, UriAssertions>(uri)
{
    private readonly Uri? _uri = uri;

    protected override string Identifier => "uri";

    public AndConstraint<UriAssertions> HaveHost(
        string host,
        string because = "")
    {
        Execute.Assertion
            .BecauseOf(because)
            .ForCondition(_uri is not null)
            .FailWith("You can't assert a uri if it is null {reason}")
            .Then
            .ForCondition(_uri!.Host == host)
            .FailWith("Expected host to contain {0}{reason}, but found {1}",
                host,
                _uri!.Host);

        return new AndConstraint<UriAssertions>(this);
    }
}