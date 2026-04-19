import { useEffect, useMemo, useState } from 'react'
import type { FormEvent } from 'react'
import { ConfirmDialog } from './components/ConfirmDialog'
import { ToastRegion } from './components/ToastRegion'
import { useInactivityLock } from './hooks/useInactivityLock'
import { useToasts } from './hooks/useToasts'
import {
  createEntry,
  deleteEntry,
  getEntries,
  getVaultState,
  resetVault,
  setupVault,
  unlockVault,
  updateEntry,
} from './services/api'
import {
  copyToClipboardWithAutoClear,
  decryptCredential,
  deriveVaultKey,
  encryptCredential,
  generatePassword,
  getDefaultGeneratorOptions,
} from './services/crypto'
import type { GeneratorOptions, VaultCredential, VaultPayload, VaultState } from './types'
import './App.css'

const AUTO_LOCK_TIMEOUT_MS = 5 * 60 * 1000

const EMPTY_FORM: VaultPayload = {
  site: '',
  username: '',
  password: '',
}

function App() {
  const [vaultState, setVaultState] = useState<VaultState | null>(null)
  const [masterPassword, setMasterPassword] = useState('')
  const [sessionToken, setSessionToken] = useState('')
  const [aesKey, setAesKey] = useState<CryptoKey | null>(null)
  const [credentials, setCredentials] = useState<VaultCredential[]>([])
  const [selectedId, setSelectedId] = useState<string | null>(null)
  const [searchValue, setSearchValue] = useState('')
  const [formData, setFormData] = useState<VaultPayload>(EMPTY_FORM)
  const [generatorOptions, setGeneratorOptions] = useState<GeneratorOptions>(getDefaultGeneratorOptions())
  const [busy, setBusy] = useState(false)
  const [showDeleteDialog, setShowDeleteDialog] = useState(false)
  const [showResetDialog, setShowResetDialog] = useState(false)

  const { toasts, success, error, info, removeToast } = useToasts()

  const selectedCredential = useMemo(() => {
    if (!selectedId) {
      return null
    }

    return credentials.find((item) => item.id === selectedId) ?? null
  }, [credentials, selectedId])

  const filteredCredentials = useMemo(() => {
    const query = searchValue.trim().toLowerCase()
    if (!query) {
      return credentials
    }

    return credentials.filter((item) => {
      return item.site.toLowerCase().includes(query) || item.username.toLowerCase().includes(query)
    })
  }, [credentials, searchValue])

  useEffect(() => {
    void refreshVaultState()
  }, [])

  useEffect(() => {
    if (!selectedCredential) {
      setFormData(EMPTY_FORM)
      return
    }

    setFormData({
      site: selectedCredential.site,
      username: selectedCredential.username,
      password: selectedCredential.password,
    })
  }, [selectedCredential])

  useInactivityLock({
    enabled: Boolean(sessionToken),
    timeoutMs: AUTO_LOCK_TIMEOUT_MS,
    onLock: () => {
      lockVault()
      info('Vault auto-locked due to inactivity.')
    },
  })

  async function refreshVaultState() {
    try {
      const state = await getVaultState()
      setVaultState(state)
    } catch {
      error('Cannot reach backend API. Start backend on localhost:5085.')
    }
  }

  async function handleInitialize(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()

    if (masterPassword.length < 12) {
      error('Use at least 12 characters for your master password.')
      return
    }

    try {
      setBusy(true)
      await setupVault(masterPassword)
      const latestState = await getVaultState()
      setVaultState(latestState)
      await handleUnlock(undefined, latestState)
      success('Vault initialized.')
    } catch (reason) {
      error(reason instanceof Error ? reason.message : 'Initialization failed.')
    } finally {
      setBusy(false)
    }
  }

  async function handleUnlock(event?: FormEvent<HTMLFormElement>, stateOverride?: VaultState) {
    event?.preventDefault()

    if (!masterPassword) {
      error('Master password is required.')
      return
    }

    try {
      setBusy(true)
      const latestState = stateOverride ?? (await getVaultState())
      setVaultState(latestState)

      if (!latestState.isInitialized) {
        error('Vault is not initialized yet.')
        return
      }

      const key = await deriveVaultKey(masterPassword, latestState.saltBase64, latestState.kdfIterations)
      const unlockResult = await unlockVault(masterPassword)

      setAesKey(key)
      setSessionToken(unlockResult.sessionToken)
      await loadCredentials(unlockResult.sessionToken, key)
      success('Vault unlocked.')
    } catch (reason) {
      error(reason instanceof Error ? reason.message : 'Unlock failed.')
    } finally {
      setBusy(false)
    }
  }

  async function loadCredentials(token: string, key: CryptoKey) {
    const entries = await getEntries(token)
    const nextCredentials: VaultCredential[] = []

    for (const entry of entries) {
      try {
        const decrypted = await decryptCredential(
          {
            nonceBase64: entry.nonceBase64,
            ciphertextBase64: entry.ciphertextBase64,
            tagBase64: entry.tagBase64,
          },
          key,
        )

        const normalized = normalizePayload(decrypted)
        if (!normalized.password) {
          continue
        }

        nextCredentials.push({
          id: entry.id,
          ...normalized,
        })
      } catch {
        // Ignore entry if decryption or payload parsing fails.
      }
    }

    setCredentials(nextCredentials)
    setSelectedId(nextCredentials.length > 0 ? nextCredentials[0].id : null)
  }

  async function handleSaveCredential(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()

    if (!sessionToken || !aesKey) {
      error('Unlock vault first.')
      return
    }

    const payload = {
      site: formData.site.trim(),
      username: formData.username.trim(),
      password: formData.password,
    }

    if (!payload.site || !payload.username || !payload.password) {
      error('Site, username, and password are required.')
      return
    }

    try {
      setBusy(true)
      const encrypted = await encryptCredential(payload, aesKey)
      const isEditing = Boolean(selectedId)

      if (isEditing && selectedId) {
        await updateEntry(sessionToken, selectedId, encrypted)

        setCredentials((current) =>
          current.map((item) => (item.id === selectedId ? { id: selectedId, ...payload } : item)),
        )
        success('Credential updated.')
      } else {
        const created = await createEntry(sessionToken, encrypted)
        const next = { id: created.id, ...payload }
        setCredentials((current) => [next, ...current])
        setSelectedId(created.id)
        success('Credential saved.')
      }
    } catch (reason) {
      error(reason instanceof Error ? reason.message : 'Unable to save credential.')
    } finally {
      setBusy(false)
    }
  }

  async function confirmDeleteCredential() {
    if (!sessionToken || !selectedId) {
      return
    }

    try {
      setBusy(true)
      await deleteEntry(sessionToken, selectedId)
      setCredentials((current) => current.filter((item) => item.id !== selectedId))
      setSelectedId(null)
      setShowDeleteDialog(false)
      success('Credential deleted.')
    } catch (reason) {
      error(reason instanceof Error ? reason.message : 'Unable to delete credential.')
    } finally {
      setBusy(false)
    }
  }

  function lockVault() {
    setSessionToken('')
    setAesKey(null)
    setCredentials([])
    setSelectedId(null)
    setFormData({ ...EMPTY_FORM })
    setMasterPassword('')
  }

  async function confirmResetVault() {
    try {
      setBusy(true)
      await resetVault()
      lockVault()
      setVaultState({ isInitialized: false, kdfIterations: 600000, saltBase64: '' })
      setShowResetDialog(false)
      success('Vault reset complete. Create a new master password.')
    } catch {
      error('Unable to reset vault.')
    } finally {
      setBusy(false)
    }
  }

  async function handleCopySecret(value: string, label: string) {
    if (!value) {
      return
    }

    try {
      await copyToClipboardWithAutoClear(value)
      success(`${label} copied. Clipboard clears in 12 seconds.`)
    } catch {
      error(`Unable to copy ${label.toLowerCase()}.`)
    }
  }

  function handleGenerateCredentialPassword() {
    try {
      const password = generatePassword(generatorOptions)
      setFormData((current) => ({ ...current, password }))
      info('Strong password generated.')
    } catch (reason) {
      error(reason instanceof Error ? reason.message : 'Unable to generate password.')
    }
  }

  function handleGenerateMasterPassword() {
    try {
      setMasterPassword(generatePassword({ ...generatorOptions, length: Math.max(18, generatorOptions.length) }))
      info('Master password generated.')
    } catch (reason) {
      error(reason instanceof Error ? reason.message : 'Unable to generate password.')
    }
  }

  const isUnlocked = Boolean(sessionToken)

  return (
    <div className="app">
      <header className="app-header">
        <div className="brand">
          <svg
            className="brand-logo"
            xmlns="http://www.w3.org/2000/svg"
            viewBox="0 0 64 64"
            fill="none"
            aria-hidden="true"
            focusable="false"
          >
            <rect width="64" height="64" rx="14" fill="#1e7a4c" />
            <circle cx="24" cy="26" r="11" stroke="#ffffff" strokeWidth="5" fill="none" />
            <rect x="31" y="24" width="20" height="5" rx="2" fill="#ffffff" />
            <rect x="43" y="29" width="5" height="5" rx="1" fill="#ffffff" />
            <rect x="36" y="29" width="5" height="5" rx="1" fill="#ffffff" />
          </svg>
          <div>
            <p className="eyebrow">Secure Password Manager</p>
            <h1>KEYPASSZF</h1>
          </div>
        </div>
        {isUnlocked && (
          <div className="header-actions">
            <span className="session-hint">Auto-lock: 5 minutes</span>
            <button type="button" className="ghost" onClick={lockVault}>
              Logout
            </button>
          </div>
        )}
      </header>

      {!isUnlocked && (
        <section className="card auth-card">
          <h2>{vaultState?.isInitialized ? 'Unlock Vault' : 'Create Master Password'}</h2>
          <p className="muted">Your master password never leaves this device in plain text.</p>

          <form onSubmit={vaultState?.isInitialized ? handleUnlock : handleInitialize} className="stack">
            <label htmlFor="master-password">Master Password</label>
            <input
              id="master-password"
              type="password"
              autoComplete="new-password"
              value={masterPassword}
              onChange={(event) => setMasterPassword(event.target.value)}
              placeholder="Enter a strong master password"
            />

            <fieldset className="generator-fieldset">
              <legend>Password Generator</legend>
              <div className="generator-controls">
                <label>
                  Length
                  <input
                    type="range"
                    min={12}
                    max={40}
                    value={generatorOptions.length}
                    onChange={(event) =>
                      setGeneratorOptions((current) => ({
                        ...current,
                        length: Number(event.target.value),
                      }))
                    }
                  />
                  <span>{generatorOptions.length}</span>
                </label>
                <label>
                  <input
                    type="checkbox"
                    checked={generatorOptions.includeUppercase}
                    onChange={(event) =>
                      setGeneratorOptions((current) => ({
                        ...current,
                        includeUppercase: event.target.checked,
                      }))
                    }
                  />
                  Uppercase
                </label>
                <label>
                  <input
                    type="checkbox"
                    checked={generatorOptions.includeLowercase}
                    onChange={(event) =>
                      setGeneratorOptions((current) => ({
                        ...current,
                        includeLowercase: event.target.checked,
                      }))
                    }
                  />
                  Lowercase
                </label>
                <label>
                  <input
                    type="checkbox"
                    checked={generatorOptions.includeNumbers}
                    onChange={(event) =>
                      setGeneratorOptions((current) => ({
                        ...current,
                        includeNumbers: event.target.checked,
                      }))
                    }
                  />
                  Numbers
                </label>
                <label>
                  <input
                    type="checkbox"
                    checked={generatorOptions.includeSymbols}
                    onChange={(event) =>
                      setGeneratorOptions((current) => ({
                        ...current,
                        includeSymbols: event.target.checked,
                      }))
                    }
                  />
                  Symbols
                </label>
              </div>
            </fieldset>

            <div className="actions">
              <button type="button" className="ghost" onClick={handleGenerateMasterPassword}>
                Generate
              </button>
              <button type="submit" disabled={busy}>
                {vaultState?.isInitialized ? 'Unlock' : 'Initialize'}
              </button>
              {vaultState?.isInitialized && (
                <button type="button" className="danger" onClick={() => setShowResetDialog(true)}>
                  Reset Vault
                </button>
              )}
            </div>
          </form>
        </section>
      )}

      {isUnlocked && (
        <main className="vault-layout">
          <section className="card sidebar">
            <div className="sidebar-top">
              <h2>Passwords</h2>
              <button type="button" onClick={() => setSelectedId(null)}>
                New
              </button>
            </div>

            <input
              type="search"
              className="search"
              value={searchValue}
              onChange={(event) => setSearchValue(event.target.value)}
              placeholder="Search by site or username"
              aria-label="Search passwords"
            />

            {filteredCredentials.length === 0 ? (
              <div className="empty-state">
                <h3>No passwords saved yet</h3>
                <p>Create your first credential to start building your vault.</p>
              </div>
            ) : (
              <ul className="credential-list">
                {filteredCredentials.map((credential) => (
                  <li key={credential.id}>
                    <button
                      type="button"
                      className={selectedId === credential.id ? 'credential-item active' : 'credential-item'}
                      onClick={() => setSelectedId(credential.id)}
                    >
                      <span>{credential.site}</span>
                      <small>{credential.username}</small>
                    </button>
                  </li>
                ))}
              </ul>
            )}
          </section>

          <section className="card editor">
            <h2>{selectedId ? 'Credential Details' : 'Add Credential'}</h2>
            <form className="stack" onSubmit={handleSaveCredential}>
              <label htmlFor="site">Site</label>
              <input
                id="site"
                value={formData.site}
                onChange={(event) => setFormData((current) => ({ ...current, site: event.target.value }))}
                placeholder="github.com"
              />

              <label htmlFor="username">Username</label>
              <input
                id="username"
                value={formData.username}
                onChange={(event) => setFormData((current) => ({ ...current, username: event.target.value }))}
                placeholder="you@example.com"
              />

              <label htmlFor="password">Password</label>
              <input
                id="password"
                type="text"
                value={formData.password}
                onChange={(event) => setFormData((current) => ({ ...current, password: event.target.value }))}
                placeholder="Stored encrypted"
              />

              <div className="actions split">
                <button type="button" className="ghost" onClick={handleGenerateCredentialPassword}>
                  Generate Password
                </button>
                <button
                  type="button"
                  className="ghost"
                  onClick={() => void handleCopySecret(formData.password, 'Password')}
                >
                  Copy Password
                </button>
              </div>

              <fieldset className="generator-fieldset compact">
                <legend>Generator Options</legend>
                <div className="generator-controls compact">
                  <label>
                    Length
                    <input
                      type="number"
                      min={8}
                      max={64}
                      value={generatorOptions.length}
                      onChange={(event) =>
                        setGeneratorOptions((current) => ({
                          ...current,
                          length: Number(event.target.value),
                        }))
                      }
                    />
                  </label>
                  <label>
                    <input
                      type="checkbox"
                      checked={generatorOptions.includeUppercase}
                      onChange={(event) =>
                        setGeneratorOptions((current) => ({
                          ...current,
                          includeUppercase: event.target.checked,
                        }))
                      }
                    />
                    Uppercase
                  </label>
                  <label>
                    <input
                      type="checkbox"
                      checked={generatorOptions.includeLowercase}
                      onChange={(event) =>
                        setGeneratorOptions((current) => ({
                          ...current,
                          includeLowercase: event.target.checked,
                        }))
                      }
                    />
                    Lowercase
                  </label>
                  <label>
                    <input
                      type="checkbox"
                      checked={generatorOptions.includeNumbers}
                      onChange={(event) =>
                        setGeneratorOptions((current) => ({
                          ...current,
                          includeNumbers: event.target.checked,
                        }))
                      }
                    />
                    Numbers
                  </label>
                  <label>
                    <input
                      type="checkbox"
                      checked={generatorOptions.includeSymbols}
                      onChange={(event) =>
                        setGeneratorOptions((current) => ({
                          ...current,
                          includeSymbols: event.target.checked,
                        }))
                      }
                    />
                    Symbols
                  </label>
                </div>
              </fieldset>

              <div className="actions split">
                <button type="submit" disabled={busy}>
                  {selectedId ? 'Save Changes' : 'Save Password'}
                </button>
                <button
                  type="button"
                  className="danger"
                  disabled={!selectedId || busy}
                  onClick={() => setShowDeleteDialog(true)}
                >
                  Delete
                </button>
              </div>
            </form>
          </section>
        </main>
      )}

      <ToastRegion toasts={toasts} onDismiss={removeToast} />

      <ConfirmDialog
        open={showDeleteDialog}
        title="Delete credential"
        message="This action cannot be undone. Do you want to continue?"
        confirmLabel="Delete"
        tone="danger"
        onConfirm={() => void confirmDeleteCredential()}
        onCancel={() => setShowDeleteDialog(false)}
      />

      <ConfirmDialog
        open={showResetDialog}
        title="Reset vault"
        message="Resetting will permanently remove every encrypted entry in this vault."
        confirmLabel="Reset Vault"
        tone="danger"
        onConfirm={() => void confirmResetVault()}
        onCancel={() => setShowResetDialog(false)}
      />
    </div>
  )
}

function normalizePayload(payload: VaultPayload | Record<string, unknown>): VaultPayload {
  const record = payload as Record<string, unknown>

  const legacySite = asString(record.website) ?? asString(record.domain)
  const legacyUsername = asString(record.email)

  return {
    site: asString(record.site) ?? legacySite ?? '',
    username: asString(record.username) ?? legacyUsername ?? '',
    password: asString(record.password) ?? '',
  }
}

function asString(value: unknown): string | undefined {
  return typeof value === 'string' ? value : undefined
}

export default App
