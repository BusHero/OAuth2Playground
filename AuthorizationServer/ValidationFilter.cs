using FluentValidation;

namespace AuthorizationServer;

internal sealed class ValidationFilter<T> : IEndpointFilter where T : class
{
    public async ValueTask<object?> InvokeAsync(
        EndpointFilterInvocationContext ctx,
        EndpointFilterDelegate next)
    {
        var validator = ctx.HttpContext.RequestServices.GetService<IValidator<T>>();

        if (validator is not null)
        {
            var entity = ctx.GetArgument<T?>(0);

            if (entity is not null)
            {
                var validation = await validator.ValidateAsync(entity);
                if (validation.IsValid)
                {
                    return await next(ctx);
                }

                return Results.ValidationProblem(validation.ToDictionary());
            }

            return Results.ValidationProblem(new Dictionary<string, string[]>
            {
                ["reqId"] = ["requestId is mandatory",],
            });
        }

        return await next(ctx);
    }
}