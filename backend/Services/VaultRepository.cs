using System.Text.Json;
using backend.Models;

namespace backend.Services;

public sealed class VaultRepository
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        WriteIndented = true
    };

    private readonly SemaphoreSlim _lock = new(1, 1);
    private readonly string _vaultPath;

    public VaultRepository(IWebHostEnvironment environment)
    {
        var dataDir = Path.Combine(environment.ContentRootPath, "App_Data");
        Directory.CreateDirectory(dataDir);
        _vaultPath = Path.Combine(dataDir, "vault.json");
    }

    public async Task<VaultState> GetAsync(CancellationToken cancellationToken = default)
    {
        await _lock.WaitAsync(cancellationToken);
        try
        {
            if (!File.Exists(_vaultPath))
            {
                return new VaultState();
            }

            await using var stream = File.OpenRead(_vaultPath);
            var state = await JsonSerializer.DeserializeAsync<VaultState>(stream, JsonOptions, cancellationToken);
            return state ?? new VaultState();
        }
        finally
        {
            _lock.Release();
        }
    }

    public async Task SaveAsync(VaultState state, CancellationToken cancellationToken = default)
    {
        await _lock.WaitAsync(cancellationToken);
        try
        {
            await using var stream = File.Create(_vaultPath);
            await JsonSerializer.SerializeAsync(stream, state, JsonOptions, cancellationToken);
        }
        finally
        {
            _lock.Release();
        }
    }
}
