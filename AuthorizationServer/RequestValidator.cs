namespace AuthorizationServer;

using FluentValidation;

internal sealed class RequestValidator 
    : AbstractValidator<Request>
{
    public RequestValidator()
    {
        RuleFor(x => x.RequestId)
            .NotEmpty()
            .OverridePropertyName("reqId");
    }
}