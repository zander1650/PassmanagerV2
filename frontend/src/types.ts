export type VaultState = {
  isInitialized: boolean
  kdfIterations: number
  saltBase64: string
}

export type ServerEntry = {
  id: string
  nonceBase64: string
  ciphertextBase64: string
  tagBase64: string
  createdAtUtc: string
  updatedAtUtc: string
}

export type VaultCredential = {
  id: string
  site: string
  username: string
  password: string
}

export type VaultPayload = Omit<VaultCredential, 'id'>

export type UnlockResponse = {
  ok: boolean
  sessionToken: string
  expiresAtUtc: string
}

export type GeneratorOptions = {
  length: number
  includeUppercase: boolean
  includeLowercase: boolean
  includeNumbers: boolean
  includeSymbols: boolean
}

export type ToastTone = 'success' | 'error' | 'info'

export type Toast = {
  id: string
  message: string
  tone: ToastTone
}
