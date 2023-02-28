/* eslint-disable no-console */
/* eslint-disable @typescript-eslint/no-unsafe-member-access */
/* eslint-disable @typescript-eslint/no-unsafe-call */
/* eslint-disable @typescript-eslint/no-unused-vars */
/* eslint-disable @typescript-eslint/no-explicit-any */
/* eslint-disable @typescript-eslint/require-await */
import {
  IAgentContext,
  IIdentifier,
  IKey,
  IKeyManager,
  IService,
} from "@veramo/core";
import elliptic from "elliptic";
import * as jose from "jose";
import { AbstractIdentifierProvider } from "@veramo/did-manager";
import { EbsiKeyCreateIdentifierOptions } from "./types/ebsikey-provider-types";
import { util } from "@cef-ebsi/key-did-resolver";

type IContext = IAgentContext<IKeyManager>;

/**
 * {@link @veramo/did-manager#DIDManager} identifier provider for `did:key` identifiers
 *
 * @beta This API may change without a BREAKING CHANGE notice.
 */
export class EbsiKeyDIDProvider extends AbstractIdentifierProvider {
  private defaultKms: string;

  constructor(options: { defaultKms: string }) {
    super();
    this.defaultKms = options.defaultKms;
  }

  async createIdentifier(
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    { kms, options }: { kms?: string; options?: EbsiKeyCreateIdentifierOptions },
    context: IContext
  ): Promise<Omit<IIdentifier, "provider">> {
    // TODO: look into other type options
    const type = "Secp256k1";
    let key: IKey;
    if (options?.privateKeyHex) {
      key = await context.agent.keyManagerImport({
        kms: kms || this.defaultKms,
        type,
        privateKeyHex: options.privateKeyHex,
      });
    } else {
      key = await context.agent.keyManagerCreate({
        kms: kms || this.defaultKms,
        type,
      });
    }

    const secp256k1 = new elliptic.ec("secp256k1");
    const publicKeyPoint = secp256k1
      .keyFromPublic(key.publicKeyHex, "hex")
      .getPublic();
    const x = publicKeyPoint.getX();
    const y = publicKeyPoint.getY();
    const publicKeyJwk = {
      alg: "ES256K",
      crv: "secp256k1",
      kty: "EC",
      x: x.toString("hex"),
      y: y.toString("hex"),
    };

    const did = util.createDid(publicKeyJwk);
    console.log(publicKeyJwk);

    const jwkThumbprint = await jose.calculateJwkThumbprint(
      publicKeyJwk,
      "sha256"
    );

    const kid = `${did}#${jwkThumbprint}`;
    key.kid = kid;

    const identifier: Omit<IIdentifier, "provider"> = {
      did,
      controllerKeyId: kid,
      keys: [key],
      services: [],
    };

    return identifier;
  }

  async updateIdentifier(
    args: {
      did: string;
      kms?: string | undefined;
      alias?: string | undefined;
      options?: any;
    },
    context: IAgentContext<IKeyManager>
  ): Promise<IIdentifier> {
    throw new Error("KeyDIDProvider updateIdentifier not supported yet.");
  }

  /** {@inheritDoc IMyAgentPlugin.myPluginFoo} */
  // private async ebsiPluginFoo(args: IEbsiPluginFooArgs, context: IRequiredContext): Promise<IMyAgentPluginFooResult> {
  //   // you can call other agent methods (that are declared in the `IRequiredContext`)
  //   const didDoc = await context.agent.resolveDid({ didUrl: args.did })
  //   // or emit some events
  //   await context.agent.emit('my-other-event', { foo: 'hello' })
  //   return { foobar: args.bar }
  // }

  async deleteIdentifier(
    identifier: IIdentifier,
    context: IContext
  ): Promise<boolean> {
    // eslint-disable-next-line no-restricted-syntax
    for (const { kid } of identifier.keys) {
      // eslint-disable-next-line no-await-in-loop
      await context.agent.keyManagerDelete({ kid });
    }
    return true;
  }

  async addKey(
    {
      identifier,
      key,
      options,
    }: { identifier: IIdentifier; key: IKey; options?: any },
    context: IContext
  ): Promise<any> {
    throw Error("KeyDIDProvider addKey not supported");
  }

  async addService(
    {
      identifier,
      service,
      options,
    }: { identifier: IIdentifier; service: IService; options?: any },
    context: IContext
  ): Promise<any> {
    throw Error("KeyDIDProvider addService not supported");
  }

  async removeKey(
    args: { identifier: IIdentifier; kid: string; options?: any },
    context: IContext
  ): Promise<any> {
    throw Error("KeyDIDProvider removeKey not supported");
  }

  async removeService(
    args: { identifier: IIdentifier; id: string; options?: any },
    context: IContext
  ): Promise<any> {
    throw Error("KeyDIDProvider removeService not supported");
  }
}
