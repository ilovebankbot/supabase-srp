import * as srp from 'secure-remote-password/client';
import { SignJWT } from 'jose';

// ─── Hex utilities ────────────────────────────────────────────────────────────

const hexToUint8Array = (hex: string): Uint8Array<ArrayBuffer> => {
  const buffer = new ArrayBuffer(hex.length / 2);
  const bytes = new Uint8Array(buffer);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.substring(i * 2, i * 2 + 2), 16);
  }
  return bytes;
};

// ─── E2EE (Web Crypto API — browser-compatible) ───────────────────────────────

export class BrowserE2EE {
  /**
   * Derives a 256-bit key from the SRP shared session key.
   * Converts hex → bytes before hashing so that the output matches
   * the server-side deriveKey() which also converts from hex first.
   */
  static async deriveKeyBuffer(sharedSessionKeyHex: string): Promise<ArrayBuffer> {
    const sessionKeyBytes = hexToUint8Array(sharedSessionKeyHex);
    return await globalThis.crypto.subtle.digest('SHA-256', sessionKeyBytes);
  }

  static async getAesKey(keyBuffer: ArrayBuffer): Promise<CryptoKey> {
    return await globalThis.crypto.subtle.importKey(
      'raw', keyBuffer, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']
    );
  }

  /** Encrypts with AES-256-GCM. Auth tag is appended to ciphertext by Web Crypto. */
  static async encrypt(
    plaintext: string,
    key: CryptoKey,
  ): Promise<{ ciphertextHex: string; ivHex: string }> {
    const iv = globalThis.crypto.getRandomValues(new Uint8Array(12));
    const encoded = new TextEncoder().encode(plaintext);

    const ciphertextBuffer = await globalThis.crypto.subtle.encrypt(
      { name: 'AES-GCM', iv }, key, encoded
    );

    const ciphertextHex = Array.from(new Uint8Array(ciphertextBuffer))
      .map(b => b.toString(16).padStart(2, '0')).join('');
    const ivHex = Array.from(iv)
      .map(b => b.toString(16).padStart(2, '0')).join('');

    return { ciphertextHex, ivHex };
  }

  static async decrypt(ciphertextHex: string, key: CryptoKey, ivHex: string): Promise<string> {
    const iv = hexToUint8Array(ivHex);
    const ciphertext = hexToUint8Array(ciphertextHex);

    const decryptedBuffer = await globalThis.crypto.subtle.decrypt(
      { name: 'AES-GCM', iv }, key, ciphertext
    );
    return new TextDecoder().decode(decryptedBuffer);
  }
}

// ─── Types ────────────────────────────────────────────────────────────────────

export interface SrpSession {
  key: string;
  proof: string;
}

export interface ClientFlowResult {
  clientPublic: string;
  clientProof: string;
  clientSession: SrpSession;
  token: string;
  ciphertextHex: string;
  ivHex: string;
}

// ─── Client flow ──────────────────────────────────────────────────────────────

export async function runClientFlow(
  username: string,
  password: string,
  serverEphemeralPublic: string,
  serverSalt: string,
): Promise<ClientFlowResult> {
  console.log(`\n=== [Browser Client] Start Flow ===`);

  const privateKey = srp.derivePrivateKey(serverSalt, username, password);
  const clientEphemeral = srp.generateEphemeral();
  console.log(`[Browser Client] Ephemeral A: ${clientEphemeral.public}`);

  const clientSession = srp.deriveSession(
    clientEphemeral.secret, serverEphemeralPublic, serverSalt, username, privateKey
  );
  console.log(`[Browser Client] Session Key: ${clientSession.key}`);

  // Derive 32-byte key for both AES-GCM encryption and JWT signing (HS256)
  const keyBuffer = await BrowserE2EE.deriveKeyBuffer(clientSession.key);
  const aesKey = await BrowserE2EE.getAesKey(keyBuffer);
  const hmacSecret = new Uint8Array(keyBuffer);

  // Sign JWT — uses the derived key directly (no second hash layer)
  const token = await new SignJWT({ sub: username, role: 'user' })
    .setProtectedHeader({ alg: 'HS256' })
    .setIssuedAt()
    .setExpirationTime('1h')
    .sign(hmacSecret);
  console.log(`[Browser Client] Signed JWT: ${token}`);

  // Encrypt test message
  const secretMessage = 'Hello from the Browser!';
  const { ciphertextHex, ivHex } = await BrowserE2EE.encrypt(secretMessage, aesKey);
  console.log(`[Browser Client] Ciphertext: ${ciphertextHex}`);

  // Verify locally
  const decrypted = await BrowserE2EE.decrypt(ciphertextHex, aesKey, ivHex);
  console.log(`[Browser Client] Local decrypt check: "${decrypted}"`);

  return {
    clientPublic: clientEphemeral.public,
    clientProof: clientSession.proof,
    clientSession,
    token,
    ciphertextHex,
    ivHex,
  };
}

/**
 * Verifies the server's proof (M2) to complete mutual authentication.
 * Called after the server responds with its own session proof.
 * Throws if the server proof is invalid.
 */
export function verifyServerProof(
  clientEphemeralPublic: string,
  clientSession: SrpSession,
  serverProof: string,
): void {
  srp.verifySession(clientEphemeralPublic, clientSession, serverProof);
  console.log('[Browser Client] ✅ Server Proof (M2) Verified! Mutual Authentication Complete.');
}
