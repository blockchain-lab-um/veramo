/* eslint-disable @typescript-eslint/no-unsafe-member-access */
/* eslint-disable @typescript-eslint/no-unsafe-call */
/* eslint-disable @typescript-eslint/no-unused-vars */
/* eslint-disable @typescript-eslint/no-explicit-any */
/* eslint-disable @typescript-eslint/require-await */
import {
  IAgentContext,
  ICredentialPlugin,
  IIdentifier,
  IKey,
  IKeyManager,
  IResolver,
  IService,
  ManagedKeyInfo,
} from '@veramo/core'
import * as jose from 'jose'
import { AbstractIdentifierProvider } from '@veramo/did-manager'
import { onboard } from './ebsi-did-onboarding.js'
import {
  generateEbsiSubjectIdentifier,
  generateRandomEbsiSubjectIdentifier,
  privateKeyJwkToHex,
} from './ebsi-did-utils.js'
import { IEbsiCreateIdentifierOptions, IEbsiDidSupportedKeyTypes } from './types/ebsi-provider-types.js'
import ec from 'elliptic'

type IContext = IAgentContext<IKeyManager & ICredentialPlugin & IResolver>

/**
 * {@link @veramo/did-manager#DIDManager} identifier provider for `did:ebsi` identifiers
 *
 * @beta This API may change without a BREAKING CHANGE notice.
 */
export class EbsiDIDProvider extends AbstractIdentifierProvider {
  private defaultKms: string

  constructor(options: { defaultKms: string }) {
    super()
    this.defaultKms = options.defaultKms
  }

  async createIdentifier(
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    { kms, options }: { kms?: string; options?: IEbsiCreateIdentifierOptions },
    context: IContext,
  ): Promise<Omit<IIdentifier, 'provider'>> {
    if (options?.sequence && options?.sequence.length !== 32) {
      throw new Error('Subject identifier should be 16 bytes (32 characters in hex string, or Uint8Array) long')
    }

    if (options?.privateKeyHex && !options?.sequence) {
      throw new Error('Currently, subject identifier sequence should be provided along with a private key')
    }

    if (options?.privateKeyHex && options?.privateKeyHex?.length !== 64) {
      throw new Error('Private key should be 32 bytes (64 characters in hex string) long')
    }
    const keyType: IEbsiDidSupportedKeyTypes = options?.keyType || 'Secp256k1'
    if (keyType !== 'Secp256k1') {
      throw new Error('Currently, only Secp256k1 key type is supported')
    }
    let jwkThumbprint: string
    let privateKeyJwk: jose.JWK
    let privateKeyHex: string
    let publicKeyJwk: jose.JWK
    let subjectIdentifier: string
    if (options?.privateKeyHex) {
      // Import existing custom private key along with the subject identifier
      const secp256k1 = new ec.ec('secp256k1')
      privateKeyHex = options.privateKeyHex
      const privateKey = secp256k1.keyFromPrivate(privateKeyHex, 'hex')
      privateKeyJwk = {
        kty: 'EC',
        crv: 'secp256k1',
        d: privateKey.getPrivate('hex'),
        x: privateKey.getPublic().getX().toString('hex'),
        y: privateKey.getPublic().getY().toString('hex'),
      }
      publicKeyJwk = { ...privateKeyJwk }
      delete publicKeyJwk.d
      jwkThumbprint = await jose.calculateJwkThumbprint(privateKeyJwk)
      subjectIdentifier = await generateEbsiSubjectIdentifier(options.sequence)
    } else {
      // Generate new key pair
      const keys = await jose.generateKeyPair('ES256K')
      privateKeyJwk = await jose.exportJWK(keys.privateKey)
      publicKeyJwk = await jose.exportJWK(keys.publicKey)
      jwkThumbprint = await jose.calculateJwkThumbprint(privateKeyJwk, 'sha256')
      subjectIdentifier = await generateRandomEbsiSubjectIdentifier()
      privateKeyHex = await privateKeyJwkToHex(privateKeyJwk)
    }
    const kid = `did:ebsi:${subjectIdentifier}#${jwkThumbprint}`
    const did = `did:ebsi:${subjectIdentifier}`
    let key: ManagedKeyInfo
    let resolution = await context.agent.resolveDid({ didUrl: did })

    if (resolution.didDocument) {
      key = await context.agent.keyManagerImport({
        kid,
        privateKeyHex,
        type: 'Secp256k1',
        kms: this.defaultKms || 'local',
      })
      return {
        did,
        controllerKeyId: kid,
        keys: [key],
        services: [],
      } as Omit<IIdentifier, 'provider'>
    }

    if (!options?.bearer) {
      throw new Error('Bearer token is required for onboarding, it should be passed as options parameter')
    }
    const bearer = options.bearer

    key = await context.agent.keyManagerImport({
      kid,
      privateKeyHex,
      type: 'Secp256k1',
      kms: this.defaultKms || 'local',
    })

    const identifier = {
      did,
      controllerKeyId: kid,
      keys: [key],
      services: [],
    }

    const keyJwks = {
      privateKeyJwk,
      publicKeyJwk,
    }
    const onboardedResult = await onboard({ bearer, identifier, keyJwks })

    if (!onboardedResult) {
      throw new Error('Unknown error while creating identifier (onboarding unsuccessful)')
    }

    if (!onboardedResult.result || !onboardedResult.result.startsWith('0x')) {
      throw new Error(`Error while creating identifier: ${JSON.stringify(onboardedResult.error, null, 2)}`)
    }

    return identifier
  }

  async updateIdentifier(
    args: {
      did: string
      kms?: string | undefined
      alias?: string | undefined
      options?: any
    },
    context: IAgentContext<IKeyManager>,
  ): Promise<IIdentifier> {
    throw new Error('KeyDIDProvider updateIdentifier not supported yet.')
  }

  async deleteIdentifier(identifier: IIdentifier, context: IContext): Promise<boolean> {
    // eslint-disable-next-line no-restricted-syntax
    for (const { kid } of identifier.keys) {
      // eslint-disable-next-line no-await-in-loop
      await context.agent.keyManagerDelete({ kid })
    }
    return true
  }

  async addKey(
    { identifier, key, options }: { identifier: IIdentifier; key: IKey; options?: any },
    context: IContext,
  ): Promise<any> {
    throw Error('KeyDIDProvider addKey not supported')
  }

  async addService(
    { identifier, service, options }: { identifier: IIdentifier; service: IService; options?: any },
    context: IContext,
  ): Promise<any> {
    throw Error('KeyDIDProvider addService not supported')
  }

  async removeKey(
    args: { identifier: IIdentifier; kid: string; options?: any },
    context: IContext,
  ): Promise<any> {
    throw Error('KeyDIDProvider removeKey not supported')
  }

  async removeService(
    args: { identifier: IIdentifier; id: string; options?: any },
    context: IContext,
  ): Promise<any> {
    throw Error('KeyDIDProvider removeService not supported')
  }
}
