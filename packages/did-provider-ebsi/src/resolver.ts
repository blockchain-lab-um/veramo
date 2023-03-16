import { Resolver } from "did-resolver";
import { getResolver } from "@cef-ebsi/ebsi-did-resolver";
import {
  DIDResolutionOptions,
  DIDResolutionResult,
  DIDResolver,
  ParsedDID,
  Resolvable,
} from "did-resolver";

const resolveDidEbsi: DIDResolver = async (
  did: string,
  parsed: ParsedDID,
  resolver: Resolvable,
  options: DIDResolutionOptions
): Promise<DIDResolutionResult> => {
  try {
    const resolverConfig = {
      registry: "https://api-pilot.ebsi.eu/did-registry/v3/identifiers",
    };
    const ebsiResolver = getResolver(resolverConfig);
    const didResolver = new Resolver(ebsiResolver);

    const didResolution = await didResolver.resolve(did);
    return didResolution;
  } catch (err: any) {
    return {
      didDocumentMetadata: {},
      didResolutionMetadata: { error: "invalidDid", message: err.toString() },
      didDocument: null,
    };
  }
};

/**
 * Provides a mapping to a did:ebsi resolver, usable by {@link did-resolver#Resolver}.
 *
 * @public
 */
export function getDidEbsiResolver() {
  return { ebsi: resolveDidEbsi };
}
