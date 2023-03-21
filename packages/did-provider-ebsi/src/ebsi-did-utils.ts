import * as jose from 'jose'
import { base58btc } from 'multiformats/bases/base58'
import { randomBytes } from 'crypto'
import { DIDDocument } from 'did-resolver'
import { IEbsiDidSupportedEcdsaAlgo, IEbsiDidSupportedKeyTypes } from './types/ebsi-provider-types'

export const algoMap: Record<IEbsiDidSupportedKeyTypes, IEbsiDidSupportedEcdsaAlgo> = {
  'P-256': 'ES256',
  Secp256k1: 'ES256K',
}

export async function generateRandomEbsiSubjectIdentifier(): Promise<string> {
  return Buffer.from(base58btc.encode(Buffer.concat([new Uint8Array([1]), randomBytes(16)]))).toString()
}

export async function generateEbsiSubjectIdentifier(
  sequence: Uint8Array | string | undefined,
): Promise<string> {
  if (!sequence) {
    throw new Error('Sequence is undefined')
  }
  if (sequence instanceof Uint8Array) {
    return Buffer.from(base58btc.encode(Buffer.concat([new Uint8Array([1]), sequence]))).toString()
  }

  return Buffer.from(
    base58btc.encode(Buffer.concat([new Uint8Array([1]), Buffer.from(sequence, 'hex')])),
  ).toString()
}

export async function privateKeyJwkToHex(privateKeyJwk: jose.JWK) {
  if (!privateKeyJwk.d) {
    throw new Error('Key does not contain private key material')
  }
  return Buffer.from(privateKeyJwk.d, 'base64').toString('hex')
}

export async function isOwner({ didDoc, did }: { didDoc: DIDDocument; did: string }): Promise<boolean> {
  if (didDoc.id === did) {
    return true
  }
  return false
}
