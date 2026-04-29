import * as srp from 'secure-remote-password/server';
import * as srpClient from 'secure-remote-password/client';
import jwt from 'jsonwebtoken';
import { createHash } from 'node:crypto';
import { runClientFlow, verifyServerProof } from './client.js';

/**
 * Derives the same 32-byte key used by the browser client for JWT signing (HS256).
 * Must convert hex → bytes before hashing to stay consistent with client.ts's
 * BrowserE2EE.deriveKeyBuffer(), which does the same via Web Crypto.
 */
function deriveHmacKey(sharedSessionKeyHex: string): Buffer {
  return createHash('sha256').update(Buffer.from(sharedSessionKeyHex, 'hex')).digest();
}

async function runServerMock() {
  console.log(`=== [Node.js Server] Initializing ===`);
  const username = `user_browser_${Date.now()}`;
  const password = 'SuperSecretPassword123!';

  // ─── Mock DB: Registration (normally done via POST /register) ─────────────
  const salt = srpClient.generateSalt();
  const privateKey = srpClient.derivePrivateKey(salt, username, password);
  const verifier = srpClient.deriveVerifier(privateKey);
  console.log(`[Node.js Server] Mock DB — registered verifier: ${verifier}`);

  // ─── Step 1: Server receives Ephemeral A + username, responds with B + salt ─
  const serverEphemeral = srp.generateEphemeral(verifier);
  console.log(`[Node.js Server] Ephemeral B: ${serverEphemeral.public}`);

  // ─── Step 2: Browser client runs its full flow ────────────────────────────
  const clientResult = await runClientFlow(username, password, serverEphemeral.public, salt);

  // ─── Step 3: Server verifies M1 (client proof) ───────────────────────────
  console.log(`\n=== [Node.js Server] Verifying Client Proof (M1) ===`);
  const serverSession = srp.deriveSession(
    serverEphemeral.secret,
    clientResult.clientPublic,
    salt,
    username,
    verifier,
    clientResult.clientProof,
  );
  console.log(`[Node.js Server] Session Key: ${serverSession.key}`);

  // ─── Step 4: Server sends M2 → client verifies mutual authentication ──────
  console.log(`[Node.js Server] Sending Server Proof (M2): ${serverSession.proof}`);
  verifyServerProof(clientResult.clientPublic, clientResult.clientSession, serverSession.proof);

  // ─── Step 5: Server verifies JWT ─────────────────────────────────────────
  const hmacKey = deriveHmacKey(serverSession.key);
  try {
    const decoded = jwt.verify(clientResult.token, hmacKey, { algorithms: ['HS256'] });
    console.log(`[Node.js Server] ✅ JWT Verified! Payload:`, decoded);
  } catch (err: unknown) {
    console.error(`[Node.js Server] ❌ JWT Verification Failed:`, (err as Error).message);
    return;
  }

  // ─── Step 6: Store E2EE payload (server never has the decryption key) ─────
  console.log(`[Node.js Server] Storing E2EE payload to DB...`);
  console.log(`  Ciphertext : ${clientResult.ciphertextHex}`);
  console.log(`  IV         : ${clientResult.ivHex}`);
  console.log(`[Node.js Server] ✅ Stored. Server cannot decrypt without client's session key.`);
}

runServerMock().catch(console.error);
