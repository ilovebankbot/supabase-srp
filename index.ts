import 'dotenv/config';
import { createClient } from '@supabase/supabase-js';
import * as srp from 'secure-remote-password/client';
import * as srpServer from 'secure-remote-password/server';
import { createHash, randomBytes, createCipheriv, createDecipheriv } from 'node:crypto';
import type { CipherGCM, DecipherGCM } from 'node:crypto';
import jwt from 'jsonwebtoken';

const SUPABASE_URL = process.env.SUPABASE_URL ?? '';
const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY ?? '';

if (!SUPABASE_URL || !SUPABASE_SERVICE_ROLE_KEY) {
  console.warn('⚠️  Supabase environment variables are not set. Supabase calls will be skipped.');
  console.warn('Create a .env file based on .env.example with valid credentials.');
}

const supabase = (SUPABASE_URL && SUPABASE_SERVICE_ROLE_KEY)
  ? createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY)
  : null;

/**
 * Derives a 32-byte HMAC/encryption key from the SRP shared session key.
 * Converts the hex session key to bytes before hashing so that both
 * client.ts (Web Crypto) and this file produce the same output.
 */
function deriveKey(sharedSessionKeyHex: string): Buffer {
  return createHash('sha256').update(Buffer.from(sharedSessionKeyHex, 'hex')).digest();
}

class E2EE {
  private static readonly ALGORITHM = 'aes-256-gcm';

  static encrypt(plaintext: string, key: Buffer): { ciphertext: string; iv: string; authTag: string } {
    const iv = randomBytes(12);
    const cipher = createCipheriv(this.ALGORITHM, key, iv) as CipherGCM;

    let encrypted = cipher.update(plaintext, 'utf8', 'hex');
    encrypted += cipher.final('hex');

    return {
      ciphertext: encrypted,
      iv: iv.toString('hex'),
      authTag: cipher.getAuthTag().toString('hex'),
    };
  }

  static decrypt(ciphertext: string, key: Buffer, ivHex: string, authTagHex: string): string {
    const iv = Buffer.from(ivHex, 'hex');
    const authTag = Buffer.from(authTagHex, 'hex');

    const decipher = createDecipheriv(this.ALGORITHM, key, iv) as DecipherGCM;
    decipher.setAuthTag(authTag);

    let decrypted = decipher.update(ciphertext, 'hex', 'utf8');
    decrypted += decipher.final('utf8');

    return decrypted;
  }
}

async function main() {
  const username = `user_${Date.now()}`;
  const password = 'SuperSecretPassword123!';

  // ─── 1. Registration ─────────────────────────────────────────────────────
  console.log(`\n--- 1. Registration Phase (Client) ---`);
  const salt = srp.generateSalt();
  const privateKey = srp.derivePrivateKey(salt, username, password);
  const verifier = srp.deriveVerifier(privateKey);
  console.log(`[Client] Salt:     ${salt}`);
  console.log(`[Client] Verifier: ${verifier}`);

  if (supabase) {
    const { error } = await supabase.from('srp_users').insert([{ username, salt, verifier }]);
    if (error) { console.error('❌ Registration failed:', error.message); return; }
    console.log('✅ Registered user in Supabase');
  } else {
    console.log('⚠️  Skipping Supabase insert (no credentials).');
  }

  // ─── 2. SRP Challenge ────────────────────────────────────────────────────
  console.log(`\n--- 2. SRP Challenge (Login Phase) ---`);

  // Step 1: Client generates Ephemeral A
  const clientEphemeral = srp.generateEphemeral();
  console.log(`[Client] Ephemeral Public A: ${clientEphemeral.public}`);

  // Step 2: Server fetches salt + verifier, generates Ephemeral B
  let serverSalt = salt;
  let serverVerifier = verifier;
  if (supabase) {
    const { data, error } = await supabase
      .from('srp_users')
      .select('salt, verifier')
      .eq('username', username)
      .single();
    if (error || !data) { console.error('❌ Fetch failed:', error?.message); return; }
    serverSalt = data.salt;
    serverVerifier = data.verifier;
    console.log('✅ Fetched salt & verifier from Supabase');
  }

  const serverEphemeral = srpServer.generateEphemeral(serverVerifier);
  console.log(`[Server] Ephemeral Public B: ${serverEphemeral.public}`);

  // Step 3: Both sides derive the Shared Session Key
  const clientSession = srp.deriveSession(
    clientEphemeral.secret, serverEphemeral.public, serverSalt, username, privateKey
  );
  const serverSession = srpServer.deriveSession(
    serverEphemeral.secret, clientEphemeral.public, serverSalt, username, serverVerifier,
    clientSession.proof  // M1: client proves it knows the password
  );

  console.log(`\n[Client] Session Key: ${clientSession.key}`);
  console.log(`[Server] Session Key: ${serverSession.key}`);

  if (clientSession.key !== serverSession.key) {
    console.error('❌ Key Exchange Failed.'); return;
  }
  console.log('✅ Key Exchange Successful!');

  // Step 4: Mutual Authentication — server sends M2, client verifies
  srp.verifySession(clientEphemeral.public, clientSession, serverSession.proof);
  console.log('✅ Mutual Authentication (M2) verified by Client.');

  // ─── 3. JWT Authentication ───────────────────────────────────────────────
  console.log(`\n--- 3. JWT Authentication Phase ---`);
  const jwtSecret = deriveKey(clientSession.key);
  const token = jwt.sign({ sub: username, role: 'user' }, jwtSecret, {
    expiresIn: '1h',
    algorithm: 'HS256',
  });
  console.log(`[Client] Signed JWT: ${token}`);

  try {
    const decoded = jwt.verify(token, deriveKey(serverSession.key), { algorithms: ['HS256'] });
    console.log(`[Server] ✅ JWT Verified! Payload:`, decoded);
  } catch (err: unknown) {
    console.error(`[Server] ❌ JWT Verification Failed:`, (err as Error).message);
  }

  // ─── 4. E2EE Encryption ──────────────────────────────────────────────────
  console.log(`\n--- 4. E2EE Phase ---`);
  const secretMessage = 'This is a highly sensitive and secret message.';
  console.log(`[Client] Original: "${secretMessage}"`);

  const encryptionKey = deriveKey(clientSession.key);
  const { ciphertext, iv, authTag } = E2EE.encrypt(secretMessage, encryptionKey);
  console.log(`[Client] Ciphertext: ${ciphertext}`);

  if (supabase) {
    const { error } = await supabase.from('e2ee_messages').insert([{
      username, encrypted_data: ciphertext, iv, auth_tag: authTag,
    }]);
    if (error) { console.error('❌ Save failed:', error.message); return; }
    console.log('✅ Saved encrypted message to Supabase');
  }

  // ─── 5. E2EE Decryption ──────────────────────────────────────────────────
  console.log(`\n--- 5. Decryption Phase ---`);
  let storedCiphertext = ciphertext;
  let storedIv = iv;
  let storedAuthTag = authTag;

  if (supabase) {
    const { data, error } = await supabase
      .from('e2ee_messages')
      .select('encrypted_data, iv, auth_tag')
      .eq('username', username)
      .order('created_at', { ascending: false })
      .limit(1)
      .single();
    if (error || !data) { console.error('❌ Fetch failed:', error?.message); return; }
    storedCiphertext = data.encrypted_data;
    storedIv = data.iv;
    storedAuthTag = data.auth_tag;
    console.log('✅ Fetched encrypted message from Supabase');
  }

  try {
    const decrypted = E2EE.decrypt(storedCiphertext, encryptionKey, storedIv, storedAuthTag);
    console.log(`[Client] Decrypted: "${decrypted}"`);
    if (decrypted === secretMessage) {
      console.log('✅ E2EE Successful! Decrypted message matches original.');
    }
  } catch (err: unknown) {
    console.error('❌ Decryption Failed:', (err as Error).message);
  }
}

main().catch(console.error);
