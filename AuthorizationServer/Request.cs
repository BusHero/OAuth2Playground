using Microsoft.AspNetCore.Mvc;

namespace AuthorizationServer;

internal sealed class Request
{
    [FromForm(Name = "reqId")] public required string RequestId { get; init; }

    [FromForm(Name = "approve")] public string? Approve { get; init; }
}