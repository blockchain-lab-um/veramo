import { DIDResolutionResult } from '@veramo/core'
import { DIDResolutionOptions, ParsedDID, Resolvable } from 'did-resolver'
import { Resolver } from 'did-resolver'
import { getResolver } from '@cef-ebsi/key-did-resolver'

export const resolveDidEbsiKey = async (
  did: string,
  parsed: ParsedDID,
  resolver: Resolvable,
  options: DIDResolutionOptions,
): Promise<DIDResolutionResult> => {
  try {
    const keyResolver = getResolver()
    const didResolver = new Resolver(keyResolver)
    const didDoc = await didResolver.resolve(did)
    return didDoc
  } catch (err: any) {
    return {
      didDocumentMetadata: {},
      didResolutionMetadata: {
        error: err.message,
      },
      didDocument: null,
    } as DIDResolutionResult
  }
}

/**
 * Provides a mapping to a did:key resolver for ebsi natural persons, usable by {@link did-resolver#Resolver}.
 *
 * @public
 */
export function getDidEbsiKeyResolver() {
  return { key: resolveDidEbsiKey }
}
