// Conversion between the server's WebAuthn JSON options/responses and the
// browser's ArrayBuffer-based Credential Management API.

function b64urlToBuf(s: string): ArrayBuffer {
  const pad = "=".repeat((4 - (s.length % 4)) % 4);
  const bin = atob((s + pad).replace(/-/g, "+").replace(/_/g, "/"));
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out.buffer;
}

function bufToB64url(buf: ArrayBuffer | null): string | undefined {
  if (!buf) return undefined;
  const bytes = new Uint8Array(buf);
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

interface JsonDescriptor {
  id: string;
  type: "public-key";
  transports?: AuthenticatorTransport[];
}

interface CreationJSON {
  publicKey: Omit<PublicKeyCredentialCreationOptions, "challenge" | "user" | "excludeCredentials"> & {
    challenge: string;
    user: { id: string; name: string; displayName: string };
    excludeCredentials?: JsonDescriptor[];
  };
}

interface RequestJSON {
  publicKey: Omit<PublicKeyCredentialRequestOptions, "challenge" | "allowCredentials"> & {
    challenge: string;
    allowCredentials?: JsonDescriptor[];
  };
}

const desc = (d: JsonDescriptor): PublicKeyCredentialDescriptor => ({
  id: b64urlToBuf(d.id),
  type: d.type,
  ...(d.transports ? { transports: d.transports } : {}),
});

export function supported(): boolean {
  return typeof window !== "undefined" && "PublicKeyCredential" in window && !!navigator.credentials;
}

export async function createPasskey(options: unknown): Promise<unknown> {
  const o = (options as CreationJSON).publicKey;
  const cred = (await navigator.credentials.create({
    publicKey: {
      ...o,
      challenge: b64urlToBuf(o.challenge),
      user: { ...o.user, id: b64urlToBuf(o.user.id) },
      excludeCredentials: (o.excludeCredentials ?? []).map(desc),
    },
  })) as PublicKeyCredential | null;
  if (!cred) throw new Error("cancelled");
  const r = cred.response as AuthenticatorAttestationResponse;
  return {
    id: cred.id,
    rawId: bufToB64url(cred.rawId),
    type: cred.type,
    authenticatorAttachment: cred.authenticatorAttachment ?? undefined,
    clientExtensionResults: cred.getClientExtensionResults(),
    response: {
      clientDataJSON: bufToB64url(r.clientDataJSON),
      attestationObject: bufToB64url(r.attestationObject),
      transports: typeof r.getTransports === "function" ? r.getTransports() : [],
    },
  };
}

export async function getPasskey(options: unknown): Promise<unknown> {
  const o = (options as RequestJSON).publicKey;
  const cred = (await navigator.credentials.get({
    publicKey: {
      ...o,
      challenge: b64urlToBuf(o.challenge),
      allowCredentials: (o.allowCredentials ?? []).map(desc),
    },
  })) as PublicKeyCredential | null;
  if (!cred) throw new Error("cancelled");
  const r = cred.response as AuthenticatorAssertionResponse;
  return {
    id: cred.id,
    rawId: bufToB64url(cred.rawId),
    type: cred.type,
    authenticatorAttachment: cred.authenticatorAttachment ?? undefined,
    clientExtensionResults: cred.getClientExtensionResults(),
    response: {
      clientDataJSON: bufToB64url(r.clientDataJSON),
      authenticatorData: bufToB64url(r.authenticatorData),
      signature: bufToB64url(r.signature),
      userHandle: bufToB64url(r.userHandle),
    },
  };
}
