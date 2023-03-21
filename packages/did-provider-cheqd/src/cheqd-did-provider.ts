import { IIdentifier, IKey, IService, IAgentContext, IKeyManager, DIDDocument } from '@veramo/core-types'
import { AbstractIdentifierProvider } from '@veramo/did-manager'

type IContext = IAgentContext<IKeyManager>

export class CheqdDIDProvider extends AbstractIdentifierProvider {
    private defaultKms: string

  constructor(options: { defaultKms: string }) {
    super()
    this.defaultKms = options.defaultKms
  }

  async createIdentifier(
    { kms, alias }: { kms?: string; alias?: string },
    context: IContext
  ): Promise<Omit<IIdentifier, 'provider'>> {
    throw new Error('not_implemented: createIdentifier')
  }

  async deleteIdentifier(identity: IIdentifier, context: IContext): Promise<boolean> {
    throw new Error('not_implemented: deleteIdentifier')
  }

  async addKey(
    { identifier, key, options }: { identifier: IIdentifier; key: IKey; options?: any },
    context: IContext
  ): Promise<any> {
    throw new Error('not_implemented: addKey')
  }

  async addService(
    { identifier, service, options }: { identifier: IIdentifier; service: IService; options?: any },
    context: IContext
  ): Promise<any> {
    throw new Error('not_implemented: addService')
  }

  async removeKey(args: { identifier: IIdentifier; kid: string; options?: any }, context: IContext): Promise<any> {
    throw new Error('not_implemented: removeKey')
  }

  async removeService(args: { identifier: IIdentifier; id: string; options?: any }, context: IContext): Promise<any> {
    throw new Error('not_implemented: removeService')
  }

  updateIdentifier?(args: { did: string; document: Partial<DIDDocument>; options?: { [x: string]: any } }, context: IContext): Promise<IIdentifier> {
    throw new Error('not_implemented: updateIdentifier')
  }
}