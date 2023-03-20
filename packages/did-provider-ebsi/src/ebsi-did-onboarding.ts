import {
  createVerifiablePresentationJwt,
  EbsiIssuer,
  EbsiVerifiablePresentation,
} from '@cef-ebsi/verifiable-presentation'
import { IIdentifier } from '@veramo/core'
import * as jose from 'jose'
import {
  IKeyJwks,
  IRPCResult,
  ISession,
  IVerifiableAuthorization,
  IVerifiablePresentation,
} from './types/ebsi-provider-types'
import { v4 as uuidv4 } from 'uuid'
import { randomBytes } from 'crypto'
import { ethers } from 'ethers'
import { Agent } from '@cef-ebsi/siop-auth'
import { privateKeyJwkToHex } from './ebsi-did-utils'
import { EbsiConfig, EbsiEndpoints } from './constants'

// Main onboard function to call when creating a new identifier
export async function onboard(args: {
  bearer: string
  keyJwks: IKeyJwks
  identifier: Omit<IIdentifier, 'provider'>
}): Promise<any> {
  if (!args.identifier.controllerKeyId) {
    throw new Error('Missing controllerKeyId')
  }
  const kid = args.identifier.controllerKeyId
  const subject = kid.split('#')[1]
  const idToken = {
    sub: subject,
    sub_jwk: args.keyJwks.publicKeyJwk,
    nonce: uuidv4(),
    responseMode: 'form_post',
  }

  const privateKey = await jose.importJWK(args.keyJwks.privateKeyJwk, 'ES256K')
  const idTokenJwt = await new jose.SignJWT(idToken)
    .setProtectedHeader({ alg: 'ES256K', typ: 'JWT', kid })
    .setIssuedAt()
    .setAudience(`${EbsiConfig.BASE_URL}${EbsiEndpoints.AUTH_RESPONSE}`)
    .setIssuer('https://self-issued.me/v2')
    .setExpirationTime('1h')
    .sign(privateKey)

  const verifiableAuthorization = await requestVerifiableAuthorization({
    idTokenJwt,
    bearer: args.bearer,
  })

  const accessToken = await exchangeVerifiableAuthorization({
    verifiableAuthorization,
    keyJwks: args.keyJwks,
    identifier: args.identifier,
  })

  return await insertDidDocument({
    identifier: args.identifier,
    bearer: accessToken,
    keyJwks: args.keyJwks,
  })
}

export async function requestVerifiableAuthorization(args: {
  idTokenJwt: string
  bearer: string
}): Promise<IVerifiableAuthorization> {
  const authenticationResponse = await fetch(`${EbsiConfig.BASE_URL}${EbsiEndpoints.AUTH_RESPONSE}`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${args.bearer}`,
    },
    body: JSON.stringify({
      id_token: args.idTokenJwt,
    }),
  })
  if (authenticationResponse.status > 299 || authenticationResponse.status < 200) {
    throw new Error(`${JSON.stringify((await authenticationResponse.json()), null, 2)}`)
  }
  const va = (await authenticationResponse.json()) as IVerifiableAuthorization

  return va
}

async function exchangeVerifiableAuthorization(args: {
  verifiableAuthorization: IVerifiableAuthorization
  identifier: Omit<IIdentifier, 'provider'>
  keyJwks: IKeyJwks
}): Promise<string> {
  const verifiablePresentation = await createVerifiablePresentation({
    verifiableAuthorization: args.verifiableAuthorization,
    identifier: args.identifier,
    keyJwks: args.keyJwks,
  })
  const ebsiAgent = new Agent({
    privateKey: await jose.importJWK(args.keyJwks.privateKeyJwk, 'ES256K'),
    alg: 'ES256K',
    kid: args.identifier.controllerKeyId,
    siopV2: true,
  })
  const ephemeralKey = await jose.generateKeyPair('ES256K')
  const ephemeralKeyJwk = await jose.exportJWK(ephemeralKey.privateKey)

  if (!ephemeralKeyJwk.d) {
    throw new Error('There has been an error while generating ephemeral keys needed for SIOP')
  }
  const ephemeralPublicKeyJwk = { ...ephemeralKeyJwk }
  delete ephemeralPublicKeyJwk.d

  const nonce = uuidv4()

  const response = await ebsiAgent.createResponse({
    nonce,
    redirectUri: 'https://self-issued.me',
    claims: {
      encryption_key: ephemeralPublicKeyJwk,
    },
    responseMode: 'form_post',
    _vp_token: {
      presentation_submission: {
        id: uuidv4(),
        definition_id: uuidv4(),
        descriptor_map: [
          {
            id: uuidv4(),
            format: 'jwt_vp',
            path: '$',
            path_nested: {
              id: 'onboarding-input-id',
              format: 'jwt_vc',
              path: '$.vp.verifiableCredential[0]',
            },
          },
        ],
      },
    },
  })

  const body = {
    id_token: response.idToken as string,
    vp_token: verifiablePresentation.jwtVp,
  }
  const sessionResponse = await fetch(`${EbsiConfig.BASE_URL}${EbsiEndpoints.SIOP_SESSIONS}`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: new URLSearchParams(body),
  })
  if (sessionResponse.status > 299 || sessionResponse.status < 200) {
    throw new Error(`${JSON.stringify(await sessionResponse.json(), null, 2)}`)
  }

  const session = (await sessionResponse.json()) as ISession
  const accessToken = await Agent.verifyAkeResponse(session, {
    nonce,
    privateEncryptionKeyJwk: ephemeralKeyJwk,
    trustedAppsRegistry: `${EbsiConfig.TAR_REG}`,
    alg: 'ES256K',
  })

  return accessToken
}

async function createVerifiablePresentation(args: {
  verifiableAuthorization: IVerifiableAuthorization
  identifier: Omit<IIdentifier, 'provider'>
  keyJwks: IKeyJwks
}): Promise<IVerifiablePresentation> {
  const verifiableAuthorization = args.verifiableAuthorization.verifiableCredential
  if (args.identifier.controllerKeyId === undefined) {
    throw new Error('Controller Key ID undefined')
  }
  if (args.verifiableAuthorization.verifiableCredential === undefined) {
    throw new Error('Verifiable Authorization undefined')
  }
  const issuer: EbsiIssuer = {
    did: args.identifier.did,
    kid: args.identifier.controllerKeyId,
    privateKeyJwk: args.keyJwks.privateKeyJwk,
    publicKeyJwk: args.keyJwks.publicKeyJwk,
    alg: 'ES256K',
  }

  const payload = {
    id: `urn:did:${uuidv4()}`,
    '@context': ['https://www.w3.org/2018/credentials/v1'],
    type: ['VerifiablePresentation'],
    holder: args.identifier.did,
    verifiableCredential: [verifiableAuthorization],
  } as EbsiVerifiablePresentation

  const jwtVp = await createVerifiablePresentationJwt(
    payload,
    issuer,
    `${EbsiConfig.BASE_URL}${EbsiEndpoints.SIOP_SESSIONS}`,
    {
      skipValidation: true,
      ebsiAuthority: EbsiConfig.BASE_URL.replace('http://', '').replace('https://', ''),
      exp: Math.floor(Date.now() / 1000) + 900,
    },
  )
  return { jwtVp, payload }
}

async function insertDidDocument(args: {
  bearer: string
  identifier: Omit<IIdentifier, 'provider'>
  keyJwks: IKeyJwks
}): Promise<IRPCResult> {
  const didDocument = {
    '@context': ['https://www.w3.org/ns/did/v1', 'https://w3id.org/security/suites/jws-2020/v1'],
    id: args.identifier.did,
    verificationMethod: [
      {
        id: args.identifier.controllerKeyId,
        type: 'JsonWebKey2020',
        controller: args.identifier.did,
        publicKeyJwk: args.keyJwks.publicKeyJwk,
      },
    ],
    authentication: [args.identifier.controllerKeyId],
    assertionMethod: [args.identifier.controllerKeyId],
  }

  const metadata = {
    meta: randomBytes(32).toString('hex'),
  }
  const timestamp = {
    data: randomBytes(32).toString('hex'),
  }

  const privateKeyHex = await privateKeyJwkToHex(args.keyJwks.privateKeyJwk)
  const wallet = new ethers.Wallet(privateKeyHex)
  const address = await wallet.getAddress()
  const bufferDidDocument = Buffer.from(JSON.stringify(didDocument))
  const bufferTimestamp = Buffer.from(JSON.stringify(timestamp))
  const bufferMetadata = Buffer.from(JSON.stringify(metadata))
  const hashValue = ethers.utils.sha256(bufferDidDocument)

  const unsignedTxResponse = await fetch(`${EbsiConfig.BASE_URL}${EbsiEndpoints.DID_REGISTRY_RPC}`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${args.bearer}`,
    },
    body: JSON.stringify({
      jsonrpc: '2.0',
      method: 'insertDidDocument',
      id: Math.ceil(Math.random() * 1000),
      params: [
        {
          from: address,
          identifier: `0x${Buffer.from(args.identifier.did).toString('hex')}`,
          hashAlgorithmId: 1, // sha256
          hashValue,
          didVersionInfo: `0x${bufferDidDocument.toString('hex')}`,
          timestampData: `0x${bufferTimestamp.toString('hex')}`,
          didVersionMetadata: `0x${bufferMetadata.toString('hex')}`,
        },
      ],
    }),
  })
  if (unsignedTxResponse.status > 299 || unsignedTxResponse.status < 200) {
    throw new Error(`${JSON.stringify(await unsignedTxResponse.json(), null, 2)}`)
  }
  const unsignedTx = await unsignedTxResponse.json()
  const tmpChainId = unsignedTx.result.chainId
  const chainId = Number(unsignedTx.result.chainId)
  unsignedTx.result.chainId = chainId
  const signedRawTransaction = await wallet.signTransaction(
    unsignedTx.result as ethers.providers.TransactionRequest,
  )

  const { r, s, v } = ethers.utils.parseTransaction(signedRawTransaction)
  unsignedTx.result.chainId = tmpChainId
  const signedTx = {
    protocol: 'eth',
    unsignedTransaction: unsignedTx.result,
    r,
    s,
    v: `0x${Number(v).toString(16)}`,
    signedRawTransaction,
  }
  const jsonRpcBody = {
    jsonrpc: '2.0',
    method: 'sendSignedTransaction',
    params: [signedTx],
    id: Math.ceil(Math.random() * 1000),
  }

  const jsonRpcResponse = await fetch(`${EbsiConfig.BASE_URL}${EbsiEndpoints.DID_REGISTRY_RPC}`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${args.bearer}`,
    },
    body: JSON.stringify(jsonRpcBody),
  })
  const jsonRpcResult = await jsonRpcResponse.json()

  return jsonRpcResult
}
