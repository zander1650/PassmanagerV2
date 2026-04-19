using System.Collections.Concurrent;
using System.Security.Cryptography;

namespace backend.Services;

public sealed class SessionTokenService
{
    private readonly ConcurrentDictionary<string, DateTime> _tokens = new(StringComparer.Ordinal);

    public (string token, DateTime expiresAtUtc) CreateToken(TimeSpan lifetime)
    {
        CleanupExpiredTokens();

        var raw = RandomNumberGenerator.GetBytes(32);
        var token = Convert.ToBase64String(raw);
        var expiresAtUtc = DateTime.UtcNow.Add(lifetime);

        _tokens[token] = expiresAtUtc;
        return (token, expiresAtUtc);
    }

    public bool IsValid(string token)
    {
        if (!_tokens.TryGetValue(token, out var expiresAtUtc))
        {
            return false;
        }

        if (expiresAtUtc <= DateTime.UtcNow)
        {
            _tokens.TryRemove(token, out _);
            return false;
        }

        return true;
    }

    private void CleanupExpiredTokens()
    {
        var now = DateTime.UtcNow;
        foreach (var kvp in _tokens)
        {
            if (kvp.Value <= now)
            {
                _tokens.TryRemove(kvp.Key, out _);
            }
        }
    }
}
