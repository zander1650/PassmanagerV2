import type { ServerEntry, UnlockResponse, VaultState } from '../types'

const API_BASE = import.meta.env.VITE_API_BASE_URL ?? 'http://localhost:5085'

async function parseError(response: Response, fallback: string): Promise<string> {
  try {
    const payload = (await response.json()) as { message?: string }
    return payload.message ?? fallback
  } catch {
    return fallback
  }
}

export async function getVaultState(): Promise<VaultState> {
  const response = await fetch(`${API_BASE}/api/vault/state`)
  if (!response.ok) {
    throw new Error(await parseError(response, 'Unable to load vault state.'))
  }
  return (await response.json()) as VaultState
}

export async function setupVault(masterPassword: string): Promise<void> {
  const response = await fetch(`${API_BASE}/api/vault/setup`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ masterPassword }),
  })

  if (!response.ok) {
    throw new Error(await parseError(response, 'Vault setup failed.'))
  }
}

export async function unlockVault(masterPassword: string): Promise<UnlockResponse> {
  const response = await fetch(`${API_BASE}/api/vault/unlock`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ masterPassword }),
  })

  if (response.status === 401) {
    throw new Error('Master password is incorrect.')
  }

  if (!response.ok) {
    throw new Error(await parseError(response, 'Unable to unlock vault.'))
  }

  return (await response.json()) as UnlockResponse
}

export async function resetVault(): Promise<void> {
  const response = await fetch(`${API_BASE}/api/vault/reset`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ confirmation: 'RESET' }),
  })

  if (!response.ok) {
    throw new Error(await parseError(response, 'Reset failed.'))
  }
}

export async function getEntries(sessionToken: string): Promise<ServerEntry[]> {
  const response = await fetch(`${API_BASE}/api/vault/entries`, {
    headers: { 'X-Vault-Session': sessionToken },
  })

  if (!response.ok) {
    throw new Error(await parseError(response, 'Unable to load entries.'))
  }

  return (await response.json()) as ServerEntry[]
}

export async function createEntry(
  sessionToken: string,
  encrypted: { nonceBase64: string; ciphertextBase64: string; tagBase64: string },
): Promise<ServerEntry> {
  const response = await fetch(`${API_BASE}/api/vault/entries`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-Vault-Session': sessionToken,
    },
    body: JSON.stringify(encrypted),
  })

  if (!response.ok) {
    throw new Error(await parseError(response, 'Unable to save entry.'))
  }

  return (await response.json()) as ServerEntry
}

export async function updateEntry(
  sessionToken: string,
  id: string,
  encrypted: { nonceBase64: string; ciphertextBase64: string; tagBase64: string },
): Promise<ServerEntry> {
  const response = await fetch(`${API_BASE}/api/vault/entries/${id}`, {
    method: 'PUT',
    headers: {
      'Content-Type': 'application/json',
      'X-Vault-Session': sessionToken,
    },
    body: JSON.stringify(encrypted),
  })

  if (!response.ok) {
    throw new Error(await parseError(response, 'Unable to update entry.'))
  }

  return (await response.json()) as ServerEntry
}

export async function deleteEntry(sessionToken: string, id: string): Promise<void> {
  const response = await fetch(`${API_BASE}/api/vault/entries/${id}`, {
    method: 'DELETE',
    headers: { 'X-Vault-Session': sessionToken },
  })

  if (!response.ok) {
    throw new Error(await parseError(response, 'Unable to delete entry.'))
  }
}
