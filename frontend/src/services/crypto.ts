import type { GeneratorOptions, VaultPayload } from '../types'

export type EncryptedPayload = {
  nonceBase64: string
  ciphertextBase64: string
  tagBase64: string
}

const DEFAULT_GENERATOR_OPTIONS: GeneratorOptions = {
  length: 20,
  includeUppercase: true,
  includeLowercase: true,
  includeNumbers: true,
  includeSymbols: true,
}

export function getDefaultGeneratorOptions(): GeneratorOptions {
  return DEFAULT_GENERATOR_OPTIONS
}

export async function deriveVaultKey(
  masterPassword: string,
  saltBase64: string,
  iterations: number,
): Promise<CryptoKey> {
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(masterPassword),
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

export async function encryptCredential(payload: VaultPayload, key: CryptoKey): Promise<EncryptedPayload> {
  const iv = crypto.getRandomValues(new Uint8Array(12))
  const plaintext = new TextEncoder().encode(JSON.stringify(payload))
  const encrypted = new Uint8Array(
    await crypto.subtle.encrypt({ name: 'AES-GCM', iv, tagLength: 128 }, key, plaintext),
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

export async function decryptCredential(
  encrypted: EncryptedPayload,
  key: CryptoKey,
): Promise<VaultPayload | Record<string, unknown>> {
  const nonce = new Uint8Array(base64ToArrayBuffer(encrypted.nonceBase64))
  const ciphertext = new Uint8Array(base64ToArrayBuffer(encrypted.ciphertextBase64))
  const tag = new Uint8Array(base64ToArrayBuffer(encrypted.tagBase64))

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

  return JSON.parse(new TextDecoder().decode(plaintext)) as VaultPayload | Record<string, unknown>
}

export function generatePassword(options: GeneratorOptions): string {
  const upper = 'ABCDEFGHJKLMNPQRSTUVWXYZ'
  const lower = 'abcdefghijkmnopqrstuvwxyz'
  const numbers = '23456789'
  const symbols = '!@#$%^&*()-_=+[]{}:;,.?'

  const pools: string[] = []
  if (options.includeUppercase) pools.push(upper)
  if (options.includeLowercase) pools.push(lower)
  if (options.includeNumbers) pools.push(numbers)
  if (options.includeSymbols) pools.push(symbols)

  if (pools.length === 0) {
    throw new Error('Enable at least one character type.')
  }

  const alphabet = pools.join('')
  const result: string[] = []

  // Ensure each selected pool contributes at least one char.
  for (const pool of pools) {
    result.push(pickRandom(pool))
  }

  while (result.length < options.length) {
    result.push(pickRandom(alphabet))
  }

  shuffle(result)
  return result.join('')
}

export async function copyToClipboardWithAutoClear(value: string, clearDelayMs = 12000): Promise<void> {
  await navigator.clipboard.writeText(value)
  window.setTimeout(async () => {
    try {
      await navigator.clipboard.writeText('')
    } catch {
      // Clipboard clear can fail due to browser permissions.
    }
  }, clearDelayMs)
}

function pickRandom(pool: string): string {
  const index = crypto.getRandomValues(new Uint32Array(1))[0] % pool.length
  return pool[index]
}

function shuffle(items: string[]) {
  for (let index = items.length - 1; index > 0; index -= 1) {
    const swapIndex = crypto.getRandomValues(new Uint32Array(1))[0] % (index + 1)
    ;[items[index], items[swapIndex]] = [items[swapIndex], items[index]]
  }
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
