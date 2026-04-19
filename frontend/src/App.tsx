import { useEffect, useMemo, useState } from 'react'
import type { FormEvent } from 'react'
import './App.css'

const API_BASE = import.meta.env.VITE_API_BASE_URL ?? 'http://localhost:5085'

type VaultState = {
  isInitialized: boolean
  kdfIterations: number
  saltBase64: string
}

type ServerEntry = {
  id: string
  nonceBase64: string
  ciphertextBase64: string
  tagBase64: string
  createdAtUtc: string
  updatedAtUtc: string
}

type VaultItem = {
  id: string
  title: string
  username: string
  password: string
  website: string
  notes: string
}

type EncryptResult = {
  nonceBase64: string
  ciphertextBase64: string
  tagBase64: string
}

function App() {
  const [vaultState, setVaultState] = useState<VaultState | null>(null)
  const [masterPassword, setMasterPassword] = useState('')
  const [sessionToken, setSessionToken] = useState('')
  const [aesKey, setAesKey] = useState<CryptoKey | null>(null)
  const [items, setItems] = useState<VaultItem[]>([])
  const [selectedId, setSelectedId] = useState<string | null>(null)
  const [status, setStatus] = useState('')
  const [error, setError] = useState('')
  const [isBusy, setIsBusy] = useState(false)
  const [search, setSearch] = useState('')
  const [form, setForm] = useState({
    title: '',
    username: '',
    password: '',
    website: '',
    notes: '',
  })

  const selectedItem = useMemo(() => {
    if (!selectedId) {
      return null
    }
    return items.find((item) => item.id === selectedId) ?? null
  }, [items, selectedId])

  const filteredItems = useMemo(() => {
    const value = search.trim().toLowerCase()
    if (!value) {
      return items
    }
    return items.filter((item) => {
      return (
        item.title.toLowerCase().includes(value) ||
        item.username.toLowerCase().includes(value) ||
        item.website.toLowerCase().includes(value)
      )
    })
  }, [items, search])

  useEffect(() => {
    void loadVaultState()
  }, [])

  useEffect(() => {
    if (selectedItem) {
      setForm({
        title: selectedItem.title,
        username: selectedItem.username,
        password: selectedItem.password,
        website: selectedItem.website,
        notes: selectedItem.notes,
      })
      return
    }

    setForm({
      title: '',
      username: '',
      password: '',
      website: '',
      notes: '',
    })
  }, [selectedItem])

  async function loadVaultState() {
    try {
      const response = await fetch(`${API_BASE}/api/vault/state`)
      if (!response.ok) {
        throw new Error('Unable to load vault state.')
      }
      const data = (await response.json()) as VaultState
      setVaultState(data)
    } catch {
      setError('Could not connect to backend API. Start backend first.')
    }
  }

  async function setupVault(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    setError('')
    setStatus('')

    if (masterPassword.length < 12) {
      setError('Use at least 12 characters for the master password.')
      return
    }

    try {
      setIsBusy(true)
      const response = await fetch(`${API_BASE}/api/vault/setup`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ masterPassword }),
      })

      if (!response.ok) {
        throw new Error('Vault setup failed.')
      }

      await loadVaultState()
      await unlockVault()
      setStatus('Vault initialized and unlocked.')
    } catch {
      setError('Failed to initialize vault. Try another master password.')
    } finally {
      setIsBusy(false)
    }
  }

  async function unlockVault(event?: FormEvent<HTMLFormElement>) {
    event?.preventDefault()
    setError('')
    setStatus('')

    if (!vaultState?.isInitialized) {
      setError('Vault is not initialized.')
      return
    }

    if (!masterPassword) {
      setError('Master password is required.')
      return
    }

    try {
      setIsBusy(true)
      const key = await deriveVaultKey(masterPassword, vaultState.saltBase64, vaultState.kdfIterations)

      const response = await fetch(`${API_BASE}/api/vault/unlock`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ masterPassword }),
      })

      if (!response.ok) {
        throw new Error('Unlock failed.')
      }

      const unlockData = (await response.json()) as {
        ok: boolean
        sessionToken: string
        expiresAtUtc: string
      }

      setAesKey(key)
      setSessionToken(unlockData.sessionToken)
      setStatus('Vault unlocked.')
      await loadEntries(unlockData.sessionToken, key)
    } catch {
      setError('Incorrect master password or inaccessible vault.')
    } finally {
      setIsBusy(false)
    }
  }

  async function loadEntries(token: string, key: CryptoKey) {
    const response = await fetch(`${API_BASE}/api/vault/entries`, {
      headers: { 'X-Vault-Session': token },
    })

    if (!response.ok) {
      throw new Error('Could not load entries.')
    }

    const encryptedEntries = (await response.json()) as ServerEntry[]
    const decrypted: VaultItem[] = []

    for (const entry of encryptedEntries) {
      try {
        const data = await decryptPayload<VaultItemData>(
          {
            nonceBase64: entry.nonceBase64,
            ciphertextBase64: entry.ciphertextBase64,
            tagBase64: entry.tagBase64,
          },
          key,
        )

        decrypted.push({
          id: entry.id,
          title: data.title,
          username: data.username,
          password: data.password,
          website: data.website,
          notes: data.notes,
        })
      } catch {
        // Skip entries that fail authentication or decryption.
      }
    }

    setItems(decrypted)
    if (decrypted.length > 0 && !selectedId) {
      setSelectedId(decrypted[0].id)
    }
  }

  async function saveEntry(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (!aesKey || !sessionToken) {
      setError('Unlock the vault first.')
      return
    }

    if (!form.title.trim() || !form.password.trim()) {
      setError('Entry title and password are required.')
      return
    }

    setError('')
    setStatus('')

    const payload = await encryptPayload(
      {
        title: form.title.trim(),
        username: form.username.trim(),
        password: form.password,
        website: form.website.trim(),
        notes: form.notes.trim(),
      },
      aesKey,
    )

    try {
      setIsBusy(true)
      const isEdit = Boolean(selectedId)
      const endpoint = isEdit
        ? `${API_BASE}/api/vault/entries/${selectedId}`
        : `${API_BASE}/api/vault/entries`
      const method = isEdit ? 'PUT' : 'POST'

      const response = await fetch(endpoint, {
        method,
        headers: {
          'Content-Type': 'application/json',
          'X-Vault-Session': sessionToken,
        },
        body: JSON.stringify(payload),
      })

      if (!response.ok) {
        throw new Error('Save failed.')
      }

      const savedEntry = (await response.json()) as ServerEntry
      const normalized: VaultItem = {
        id: savedEntry.id,
        title: form.title.trim(),
        username: form.username.trim(),
        password: form.password,
        website: form.website.trim(),
        notes: form.notes.trim(),
      }

      setItems((current) => {
        if (isEdit) {
          return current.map((item) => (item.id === normalized.id ? normalized : item))
        }
        return [normalized, ...current]
      })

      setSelectedId(normalized.id)
      setStatus(isEdit ? 'Entry updated.' : 'Entry created.')
    } catch {
      setError('Unable to save entry.')
    } finally {
      setIsBusy(false)
    }
  }

  async function deleteSelected() {
    if (!selectedId || !sessionToken) {
      return
    }

    try {
      setIsBusy(true)
      const response = await fetch(`${API_BASE}/api/vault/entries/${selectedId}`, {
        method: 'DELETE',
        headers: { 'X-Vault-Session': sessionToken },
      })

      if (!response.ok) {
        throw new Error('Delete failed.')
      }

      setItems((current) => current.filter((item) => item.id !== selectedId))
      setSelectedId(null)
      setStatus('Entry deleted.')
    } catch {
      setError('Unable to delete selected entry.')
    } finally {
      setIsBusy(false)
    }
  }

  function newEntry() {
    setSelectedId(null)
    setForm({
      title: '',
      username: '',
      password: '',
      website: '',
      notes: '',
    })
  }

  function generateMasterPassword() {
    const generated = generateStrongPassword(28)
    setMasterPassword(generated)
    setStatus('Strong master password generated. Save it safely.')
    setError('')
  }

  return (
    <div className="app-shell">
      <header className="hero">
        <p className="eyebrow">PassMan v2</p>
        <h1>Personal Password Vault</h1>
        <p className="hero-copy">
          AES-GCM encrypted entries, PBKDF2 key derivation, and master-password protected access.
        </p>
      </header>

      {!sessionToken && (
        <section className="panel auth-panel">
          <h2>{vaultState?.isInitialized ? 'Unlock Vault' : 'Create Master Password'}</h2>
          <form onSubmit={vaultState?.isInitialized ? unlockVault : setupVault}>
            <label htmlFor="masterPassword">Master Password</label>
            <input
              id="masterPassword"
              type="password"
              autoComplete="new-password"
              value={masterPassword}
              onChange={(event) => setMasterPassword(event.target.value)}
              placeholder="Enter master password"
            />

            <div className="auth-actions">
              <button type="button" className="ghost" onClick={generateMasterPassword}>
                Generate Master Password
              </button>
              <button disabled={isBusy} type="submit">
                {vaultState?.isInitialized ? 'Unlock' : 'Initialize Vault'}
              </button>
            </div>
          </form>
        </section>
      )}

      {sessionToken && (
        <main className="vault-grid">
          <section className="panel sidebar">
            <div className="sidebar-head">
              <h2>Entries</h2>
              <button type="button" onClick={newEntry}>
                + New
              </button>
            </div>

            <input
              className="search"
              placeholder="Search"
              value={search}
              onChange={(event) => setSearch(event.target.value)}
            />

            <ul className="entry-list">
              {filteredItems.map((item) => (
                <li key={item.id}>
                  <button
                    type="button"
                    className={selectedId === item.id ? 'entry active' : 'entry'}
                    onClick={() => setSelectedId(item.id)}
                  >
                    <span>{item.title || 'Untitled'}</span>
                    <small>{item.username || item.website || 'No details'}</small>
                  </button>
                </li>
              ))}
            </ul>
          </section>

          <section className="panel editor">
            <h2>{selectedId ? 'Edit Entry' : 'Create Entry'}</h2>
            <form className="editor-form" onSubmit={saveEntry}>
              <label htmlFor="title">Title</label>
              <input
                id="title"
                value={form.title}
                onChange={(event) => setForm((current) => ({ ...current, title: event.target.value }))}
                placeholder="GitHub"
              />

              <label htmlFor="username">Username / Email</label>
              <input
                id="username"
                value={form.username}
                onChange={(event) => setForm((current) => ({ ...current, username: event.target.value }))}
                placeholder="you@example.com"
              />

              <label htmlFor="password">Password</label>
              <input
                id="password"
                value={form.password}
                onChange={(event) => setForm((current) => ({ ...current, password: event.target.value }))}
                placeholder="Stored encrypted"
              />

              <label htmlFor="website">Website</label>
              <input
                id="website"
                value={form.website}
                onChange={(event) => setForm((current) => ({ ...current, website: event.target.value }))}
                placeholder="https://example.com"
              />

              <label htmlFor="notes">Notes</label>
              <textarea
                id="notes"
                rows={4}
                value={form.notes}
                onChange={(event) => setForm((current) => ({ ...current, notes: event.target.value }))}
                placeholder="Recovery codes, hints, metadata"
              />

              <div className="editor-actions">
                <button disabled={isBusy} type="submit">
                  {selectedId ? 'Save Changes' : 'Save Entry'}
                </button>
                <button
                  type="button"
                  className="danger"
                  disabled={isBusy || !selectedId}
                  onClick={deleteSelected}
                >
                  Delete
                </button>
              </div>
            </form>
          </section>
        </main>
      )}

      {(status || error) && (
        <div className={error ? 'toast error' : 'toast'}>
          <span>{error || status}</span>
        </div>
      )}
    </div>
  )
}

type VaultItemData = Omit<VaultItem, 'id'>

async function deriveVaultKey(masterPassword: string, saltBase64: string, iterations: number) {
  const encoder = new TextEncoder()
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    encoder.encode(masterPassword),
    { name: 'PBKDF2' },
    false,
    ['deriveKey'],
  )

  return crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: base64ToArrayBuffer(saltBase64),
      iterations,
      hash: 'SHA-512',
    },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  )
}

async function encryptPayload(data: VaultItemData, key: CryptoKey): Promise<EncryptResult> {
  const iv = crypto.getRandomValues(new Uint8Array(12))
  const plaintext = new TextEncoder().encode(JSON.stringify(data))
  const encrypted = new Uint8Array(
    await crypto.subtle.encrypt(
      {
        name: 'AES-GCM',
        iv,
        tagLength: 128,
      },
      key,
      plaintext,
    ),
  )

  const tagStart = encrypted.length - 16
  const ciphertext = encrypted.slice(0, tagStart)
  const tag = encrypted.slice(tagStart)

  return {
    nonceBase64: bytesToBase64(iv),
    ciphertextBase64: bytesToBase64(ciphertext),
    tagBase64: bytesToBase64(tag),
  }
}

async function decryptPayload<T>(payload: EncryptResult, key: CryptoKey): Promise<T> {
  const nonce = new Uint8Array(base64ToArrayBuffer(payload.nonceBase64))
  const ciphertext = new Uint8Array(base64ToArrayBuffer(payload.ciphertextBase64))
  const tag = new Uint8Array(base64ToArrayBuffer(payload.tagBase64))

  const combined = new Uint8Array(ciphertext.length + tag.length)
  combined.set(ciphertext)
  combined.set(tag, ciphertext.length)

  const plaintext = await crypto.subtle.decrypt(
    {
      name: 'AES-GCM',
      iv: nonce,
      tagLength: 128,
    },
    key,
    combined,
  )

  const json = new TextDecoder().decode(plaintext)
  return JSON.parse(json) as T
}

function bytesToBase64(bytes: Uint8Array): string {
  let binary = ''
  for (let index = 0; index < bytes.length; index += 1) {
    binary += String.fromCharCode(bytes[index])
  }
  return btoa(binary)
}

function base64ToArrayBuffer(value: string): ArrayBuffer {
  const binary = atob(value)
  const bytes = new Uint8Array(binary.length)
  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index)
  }
  return bytes.buffer.slice(0)
}

function generateStrongPassword(length: number) {
  const alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%^&*()-_=+[]{}?'
  const random = crypto.getRandomValues(new Uint32Array(length))
  let password = ''
  for (let index = 0; index < length; index += 1) {
    password += alphabet[random[index] % alphabet.length]
  }
  return password
}

export default App
