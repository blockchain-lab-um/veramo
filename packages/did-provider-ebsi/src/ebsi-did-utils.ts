import * as jose from "jose";

export async function privateKeyJwkToHex(privateKeyJwk: jose.JWK) {
  if (!privateKeyJwk.d) {
    throw new Error("Key does not contain private key material");
  }
  return Buffer.from(privateKeyJwk.d, "base64").toString("hex");
}
