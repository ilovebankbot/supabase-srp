declare module 'secure-remote-password/client' {
  export interface Session {
    key: string;
    proof: string;
  }

  export function generateSalt(): string;
  export function derivePrivateKey(salt: string, username: string, password: string): string;
  export function deriveVerifier(privateKey: string): string;
  export function generateEphemeral(): { secret: string; public: string };
  export function deriveSession(
    clientSecret: string,
    serverPublic: string,
    salt: string,
    username: string,
    privateKey: string,
  ): Session;
  /** Verifies the server's proof (M2). Throws if invalid. */
  export function verifySession(
    clientEphemeralPublic: string,
    clientSession: Session,
    serverSessionProof: string,
  ): void;
}

declare module 'secure-remote-password/server' {
  export interface Session {
    key: string;
    proof: string;
  }

  export function generateEphemeral(verifier: string): { secret: string; public: string };
  export function deriveSession(
    serverSecret: string,
    clientPublic: string,
    salt: string,
    username: string,
    verifier: string,
    clientProof: string,
  ): Session;
}
