/* eslint-disable @typescript-eslint/no-unsafe-member-access */
/* eslint-disable @typescript-eslint/no-unsafe-call */
/* eslint-disable @typescript-eslint/no-unused-vars */
/* eslint-disable @typescript-eslint/no-explicit-any */
/* eslint-disable @typescript-eslint/require-await */
import { IAgentContext, ICredentialPlugin, IIdentifier, IKey, IKeyManager, IService } from '@veramo/core'
import { base58btc } from 'multiformats/bases/base58'
import { randomBytes } from 'crypto'
import * as jose from 'jose'
import { AbstractIdentifierProvider } from '@veramo/did-manager'
import { onboard } from './ebsi-did-onboarding.js'
import { privateKeyJwkToHex } from './ebsi-did-utils.js'

type IContext = IAgentContext<IKeyManager | ICredentialPlugin>

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
    { kms, options }: { kms?: string; options?: any },
    context: IContext,
  ): Promise<Omit<IIdentifier, 'provider'>> {
    if (!options.bearer) {
      throw new Error('Bearer token should be provided in options argument')
    }
    const bearer = options.bearer as string

    const keys = await jose.generateKeyPair('ES256K')
    const privateKeyJwk = await jose.exportJWK(keys.privateKey)
    const publicKeyJwk = await jose.exportJWK(keys.publicKey)

    if (!privateKeyJwk.d || !privateKeyJwk.x || !privateKeyJwk.y) {
      throw new Error('There has been an error while generating keys')
    }

    const privateKeyHex = await privateKeyJwkToHex(privateKeyJwk)
    const jwkThumbprint = await jose.calculateJwkThumbprint(publicKeyJwk, 'sha256')
    const subjectIdentifier = Buffer.from(
      base58btc.encode(Buffer.concat([new Uint8Array([1]), randomBytes(16)])),
    ).toString()

    const kid = `did:ebsi:${subjectIdentifier}#${jwkThumbprint}`
    const did = `did:ebsi:${subjectIdentifier}`

    const key = await context.agent.keyManagerImport({
      kid,
      privateKeyHex,
      type: 'Secp256k1',
      kms: this.defaultKms || 'local',
    })

    const identifier: Omit<IIdentifier, 'provider'> = {
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

    if (identifier.keys[0].privateKeyHex) {
      delete identifier.keys[0].privateKeyHex
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
