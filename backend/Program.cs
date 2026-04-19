using backend.Models;
using backend.Services;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddOpenApi();
builder.Services.AddSingleton<VaultRepository>();
builder.Services.AddSingleton<MasterPasswordService>();
builder.Services.AddSingleton<SessionTokenService>();

builder.Services.AddCors(options =>
{
    options.AddPolicy("frontend", policy =>
    {
        policy
            .WithOrigins("http://localhost:5173")
            .AllowAnyHeader()
            .AllowAnyMethod();
    });
});

var app = builder.Build();

if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
}

app.UseHttpsRedirection();
app.UseCors("frontend");

app.MapGet("/api/vault/state", async (VaultRepository repository, CancellationToken cancellationToken) =>
{
    var state = await repository.GetAsync(cancellationToken);
    return Results.Ok(new VaultStateResponse(state.IsInitialized, state.KdfIterations, state.SaltBase64));
});

app.MapPost("/api/vault/setup", async (
    SetupVaultRequest request,
    VaultRepository repository,
    MasterPasswordService passwordService,
    CancellationToken cancellationToken) =>
{
    if (string.IsNullOrWhiteSpace(request.MasterPassword) || request.MasterPassword.Length < 12)
    {
        return Results.BadRequest(new { message = "Master password must be at least 12 characters." });
    }

    var state = await repository.GetAsync(cancellationToken);
    if (state.IsInitialized)
    {
        return Results.Conflict(new { message = "Vault is already initialized." });
    }

    state.IsInitialized = true;
    state.KdfIterations = 600000;
    state.SaltBase64 = passwordService.GenerateSaltBase64();

    var key = passwordService.DeriveKey(request.MasterPassword, state.SaltBase64, state.KdfIterations);
    var verifier = passwordService.CreateVerifier(key);

    state.VerifierNonceBase64 = verifier.nonceBase64;
    state.VerifierCiphertextBase64 = verifier.ciphertextBase64;
    state.VerifierTagBase64 = verifier.tagBase64;
    state.Entries.Clear();

    await repository.SaveAsync(state, cancellationToken);
    return Results.Ok(new { ok = true });
});

app.MapPost("/api/vault/unlock", async (
    UnlockVaultRequest request,
    VaultRepository repository,
    MasterPasswordService passwordService,
    SessionTokenService sessionTokenService,
    CancellationToken cancellationToken) =>
{
    var state = await repository.GetAsync(cancellationToken);
    if (!state.IsInitialized)
    {
        return Results.BadRequest(new { message = "Vault is not initialized." });
    }

    if (string.IsNullOrWhiteSpace(request.MasterPassword))
    {
        return Results.BadRequest(new { message = "Master password is required." });
    }

    var key = passwordService.DeriveKey(request.MasterPassword, state.SaltBase64, state.KdfIterations);
    var isValid = passwordService.VerifyMasterPassword(
        key,
        state.VerifierNonceBase64,
        state.VerifierCiphertextBase64,
        state.VerifierTagBase64
    );

    if (!isValid)
    {
        return Results.Unauthorized();
    }

    var (token, expiresAtUtc) = sessionTokenService.CreateToken(TimeSpan.FromMinutes(30));
    return Results.Ok(new UnlockVaultResponse(true, token, expiresAtUtc));
});

app.MapGet("/api/vault/entries", async (
    HttpContext context,
    VaultRepository repository,
    SessionTokenService sessionTokenService,
    CancellationToken cancellationToken) =>
{
    if (!TryValidateSession(context, sessionTokenService, out var unauthorizedResult))
    {
        return unauthorizedResult;
    }

    var state = await repository.GetAsync(cancellationToken);
    var entries = state.Entries
        .OrderByDescending(entry => entry.UpdatedAtUtc)
        .Select(entry => new VaultEntryResponse(
            entry.Id,
            entry.NonceBase64,
            entry.CiphertextBase64,
            entry.TagBase64,
            entry.CreatedAtUtc,
            entry.UpdatedAtUtc
        ));

    return Results.Ok(entries);
});

app.MapPost("/api/vault/entries", async (
    HttpContext context,
    UpsertEntryRequest request,
    VaultRepository repository,
    SessionTokenService sessionTokenService,
    CancellationToken cancellationToken) =>
{
    if (!TryValidateSession(context, sessionTokenService, out var unauthorizedResult))
    {
        return unauthorizedResult;
    }

    if (!IsValidPayload(request))
    {
        return Results.BadRequest(new { message = "Encrypted payload is invalid." });
    }

    var state = await repository.GetAsync(cancellationToken);
    var now = DateTime.UtcNow;
    var newEntry = new VaultEntry
    {
        NonceBase64 = request.NonceBase64,
        CiphertextBase64 = request.CiphertextBase64,
        TagBase64 = request.TagBase64,
        CreatedAtUtc = now,
        UpdatedAtUtc = now
    };

    state.Entries.Add(newEntry);
    await repository.SaveAsync(state, cancellationToken);

    return Results.Ok(new VaultEntryResponse(
        newEntry.Id,
        newEntry.NonceBase64,
        newEntry.CiphertextBase64,
        newEntry.TagBase64,
        newEntry.CreatedAtUtc,
        newEntry.UpdatedAtUtc
    ));
});

app.MapPut("/api/vault/entries/{id:guid}", async (
    Guid id,
    HttpContext context,
    UpsertEntryRequest request,
    VaultRepository repository,
    SessionTokenService sessionTokenService,
    CancellationToken cancellationToken) =>
{
    if (!TryValidateSession(context, sessionTokenService, out var unauthorizedResult))
    {
        return unauthorizedResult;
    }

    if (!IsValidPayload(request))
    {
        return Results.BadRequest(new { message = "Encrypted payload is invalid." });
    }

    var state = await repository.GetAsync(cancellationToken);
    var entry = state.Entries.FirstOrDefault(item => item.Id == id);
    if (entry is null)
    {
        return Results.NotFound();
    }

    entry.NonceBase64 = request.NonceBase64;
    entry.CiphertextBase64 = request.CiphertextBase64;
    entry.TagBase64 = request.TagBase64;
    entry.UpdatedAtUtc = DateTime.UtcNow;

    await repository.SaveAsync(state, cancellationToken);
    return Results.Ok(new VaultEntryResponse(
        entry.Id,
        entry.NonceBase64,
        entry.CiphertextBase64,
        entry.TagBase64,
        entry.CreatedAtUtc,
        entry.UpdatedAtUtc
    ));
});

app.MapDelete("/api/vault/entries/{id:guid}", async (
    Guid id,
    HttpContext context,
    VaultRepository repository,
    SessionTokenService sessionTokenService,
    CancellationToken cancellationToken) =>
{
    if (!TryValidateSession(context, sessionTokenService, out var unauthorizedResult))
    {
        return unauthorizedResult;
    }

    var state = await repository.GetAsync(cancellationToken);
    var removedCount = state.Entries.RemoveAll(entry => entry.Id == id);
    if (removedCount == 0)
    {
        return Results.NotFound();
    }

    await repository.SaveAsync(state, cancellationToken);
    return Results.NoContent();
});

app.Run();

static bool TryValidateSession(HttpContext context, SessionTokenService sessionTokenService, out IResult unauthorizedResult)
{
    unauthorizedResult = Results.Unauthorized();

    if (!context.Request.Headers.TryGetValue("X-Vault-Session", out var tokenValues))
    {
        return false;
    }

    var token = tokenValues.FirstOrDefault();
    if (string.IsNullOrWhiteSpace(token))
    {
        return false;
    }

    return sessionTokenService.IsValid(token);
}

static bool IsValidPayload(UpsertEntryRequest request)
{
    return !string.IsNullOrWhiteSpace(request.NonceBase64)
        && !string.IsNullOrWhiteSpace(request.CiphertextBase64)
        && !string.IsNullOrWhiteSpace(request.TagBase64);
}
