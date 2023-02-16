import type { JwkDidSupportedKeyTypes } from '.'
import { VerificationMethod, type JsonWebKey } from 'did-resolver'
import { hexToBytes, bytesToBase64url, extractPublicKeyHex } from '@veramo/utils'
import elliptic from 'elliptic'

function createJWK(keyType: string, pubKey: string | Uint8Array): JsonWebKey {
  let jwk;
  if (keyType === 'Secp256k1') {
    const EC = new elliptic.ec('secp256k1')
    const pubPoint = EC.keyFromPublic(pubKey, 'hex').getPublic()
    const x = pubPoint.getX()
    const y = pubPoint.getY()

    jwk = {
      crv: 'secp256k1',
      kty: 'EC',
      x: bytesToBase64url(hexToBytes(x.toString('hex'))),
      y: bytesToBase64url(hexToBytes(y.toString('hex'))),
    } as JsonWebKey
  } else {
    jwk = {
      crv: 'ed25519',
      kty: 'OKP',
      x: bytesToBase64url(typeof pubKey === 'string' ? hexToBytes(pubKey) : pubKey),
    } as JsonWebKey
  }
  if(!jwk) throw new Error('Failed to create JWK')
  return jwk
}

export function generateJWKfromVerificationMethod(keyType: JwkDidSupportedKeyTypes, key: VerificationMethod) {
  return createJWK(keyType, extractPublicKeyHex(key))
}
