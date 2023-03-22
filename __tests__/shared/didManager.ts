// noinspection ES6PreferShortImport

import { randomBytes } from 'crypto'
import ec from 'elliptic'
import { IDIDManager, IIdentifier, IKeyManager, TAgent } from '../../packages/core-types/src'

type ConfiguredAgent = TAgent<IDIDManager & IKeyManager>

export default (testContext: {
  getAgent: () => ConfiguredAgent
  setup: () => Promise<boolean>
  tearDown: () => Promise<boolean>
}) => {
  describe('DID manager', () => {
    let agent: ConfiguredAgent

    beforeAll(async () => {
      await testContext.setup()
      agent = testContext.getAgent()
      return true
    })
    afterAll(testContext.tearDown)

    let identifier: IIdentifier
    it('should create identifier', async () => {
      identifier = await agent.didManagerCreate({
        provider: 'did:web',
        alias: 'example.com',
      })
      expect(identifier.provider).toEqual('did:web')
      expect(identifier.alias).toEqual('example.com')
      expect(identifier.did).toEqual('did:web:example.com')
      expect(identifier.keys.length).toEqual(1)
      expect(identifier.services.length).toEqual(0)
      expect(identifier.controllerKeyId).toEqual(identifier.keys[0].kid)
    })

    it('should create pkh identifier using did:pkh provider', async () => {
      identifier = await agent.didManagerCreate({
        // this expects the `did:ethr` provider to matchPrefix and use the `arbitrum:goerli` network specifier
        provider: 'did:pkh',
        options: { chainId: "1"}
      })
      expect(identifier.provider).toEqual('did:pkh')
      //expect(identifier.did).toMatch(/^did:pkh:eip155:*$/)
      expect(identifier.keys.length).toEqual(1)
      expect(identifier.services.length).toEqual(0)
      expect(identifier.controllerKeyId).toEqual(identifier.keys[0].kid)
    })

    it('should create identifier using did:ethr:arbitrum:goerli provider', async () => {
      identifier = await agent.didManagerCreate({
        // this expects the `did:ethr` provider to matchPrefix and use the `arbitrum:goerli` network specifier
        provider: 'did:ethr:arbitrum:goerli',
      })
      expect(identifier.provider).toEqual('did:ethr:arbitrum:goerli')
      expect(identifier.did).toMatch(/^did:ethr:arbitrum:goerli:0x.*$/)
      expect(identifier.keys.length).toEqual(1)
      expect(identifier.services.length).toEqual(0)
      expect(identifier.controllerKeyId).toEqual(identifier.keys[0].kid)
    })

    it('should create identifier using chainId 3', async () => {
      identifier = await agent.didManagerCreate({
        provider: 'did:ethr',
        options: {
          // this expects the `did:ethr` provider to matchPrefix and use the `arbitrum:goerli` network specifier
          // because the configured network has that name
          network: 421613,
        },
      })
      expect(identifier.provider).toEqual('did:ethr')
      expect(identifier.did).toMatch(/^did:ethr:arbitrum:goerli:0x.*$/)
      expect(identifier.keys.length).toEqual(1)
      expect(identifier.services.length).toEqual(0)
      expect(identifier.controllerKeyId).toEqual(identifier.keys[0].kid)
    })

    it('should create identifier using did:jwk', async () => {
      // keyType supports 'Secp256k1', 'Secp256r1', 'Ed25519', 'X25519'
      const keyType = 'Ed25519'
      identifier = await agent.didManagerCreate({
        provider: 'did:jwk',
        options: {
          keyType,
        }
      })
      expect(identifier.provider).toEqual('did:jwk')
      expect(identifier.keys[0].type).toEqual(keyType)
      expect(identifier.controllerKeyId).toEqual(identifier.keys[0].kid)
    })
    it('should create identifier using did:jwk with an imported key', async () => {
      // keyType supports 'Secp256k1', 'Secp256r1', 'Ed25519', 'X25519'
      const keyType = 'Ed25519'
      identifier = await agent.didManagerCreate({
        provider: 'did:jwk',
        options: {
          keyType,
          privateKeyHex: 'f3157fbbb356a0d56a84a1a9752f81d0638cce4153168bd1b46f68a6e62b82b0f3157fbbb356a0d56a84a1a9752f81d0638cce4153168bd1b46f68a6e62b82b0',
        }
      })
      expect(identifier.provider).toEqual('did:jwk')
      expect(identifier.keys[0].type).toEqual(keyType)
      expect(identifier.controllerKeyId).toEqual(identifier.keys[0].kid)
    })
    it('should create identifier using did:jwk with a default imported key', async () => {
      // keyType supports 'Secp256k1', 'Secp256r1', 'Ed25519', 'X25519'
      const keyType = 'Secp256k1'
      identifier = await agent.didManagerCreate({
        provider: 'did:jwk',
        options: {
          privateKeyHex: 'f3157fbbb356a0d56a84a1a9752f81d0638cce4153168bd1b46f68a6e62b82b0',
        }
      })
      expect(identifier.provider).toEqual('did:jwk')
      expect(identifier.keys[0].type).toEqual(keyType)
      expect(identifier.controllerKeyId).toEqual(identifier.keys[0].kid)
    })
    it('should throw error for invalid privateKEyHex', async () => {
      await expect( agent.didManagerCreate({
        provider: 'did:jwk',
        options: {
          privateKeyHex: '1234',
        }
      })).rejects.toThrow()
      expect(identifier.provider).toEqual('did:jwk')
    })
    it('should throw error for invalid keyUse parameter', async () => {
      await expect( agent.didManagerCreate({
        provider: 'did:jwk',
        options: {
          keyType: 'Secp256k1',
          keyUse: 'signing',
        }
      })).rejects.toThrow('illegal_argument: Key use must be sig or enc')
      expect(identifier.provider).toEqual('did:jwk')
    })
    it('should throw error for invalid Ed25519 key use', async () => {
      await expect( agent.didManagerCreate({
        provider: 'did:jwk',
        alias: 'test1',
        options: {
          keyType: 'Ed25519',
          keyUse: 'enc',
        }
      })).rejects.toThrow('illegal_argument: Ed25519 keys cannot be used for encryption')
      expect(identifier.provider).toEqual('did:jwk')
    })

    const itif = process.env.EBSI_BEARER ? it : it.skip
    itif('should create and onboard did:ebsi identifier, default parameters', async () => {
      identifier = await agent.didManagerCreate({
        provider: 'did:ebsi',
        options: {
          bearer: process.env.EBSI_BEARER,
        },
      })
      expect(identifier.provider).toEqual('did:ebsi')
      expect(identifier.controllerKeyId).toEqual(identifier.keys[0].kid)
      expect(identifier.keys[0].type).toEqual('Secp256k1')
    })

    itif('should create and onboard did:ebsi identifier, with private key type P-256', async () => {
      identifier = await agent.didManagerCreate({
        provider: 'did:ebsi',
        options: {
          bearer: process.env.EBSI_BEARER,
          keyType: 'P-256',
        },
      })
      expect(identifier.provider).toEqual('did:ebsi')
      expect(identifier.controllerKeyId).toEqual(identifier.keys[0].kid)
      expect(identifier.keys[0].type).toEqual('Secp256r1')
    })

    itif('should create and onboard did:ebsi identifier, with custom private key, type Secp256k1', async () => {
      const id = randomBytes(16).toString('hex')
      const curve = new ec.ec('secp256k1')
      const keyPair = curve.genKeyPair()
      const privateKeyHex = keyPair.getPrivate('hex')
      identifier = await agent.didManagerCreate({
        provider: 'did:ebsi',
        options: {
          id,
          privateKeyHex,
          bearer: process.env.EBSI_BEARER,
        },
      })
      expect(identifier.provider).toEqual('did:ebsi')
      expect(identifier.controllerKeyId).toEqual(identifier.keys[0].kid)
      expect(identifier.keys[0].type).toEqual('Secp256k1')
    })

    itif('should create and onboard did:ebsi identifier, with custom private key, type P-256', async () => {
      const id = randomBytes(16).toString('hex')
      const curve = new ec.ec('p256')
      const keyPair = curve.genKeyPair()
      const privateKeyHex = keyPair.getPrivate('hex')
      identifier = await agent.didManagerCreate({
        provider: 'did:ebsi',
        options: {
          id,
          privateKeyHex,
          bearer: process.env.EBSI_BEARER,
          keyType: 'P-256',
        },
      })
      expect(identifier.provider).toEqual('did:ebsi')
      expect(identifier.controllerKeyId).toEqual(identifier.keys[0].kid)
      expect(identifier.keys[0].type).toEqual('Secp256r1')
    })

    itif('should create identifier and onboard did using did:ebsi with all options provided', async () => {
      const id = randomBytes(16).toString('hex')
      const privateKeyHex = randomBytes(32).toString('hex')
      identifier = await agent.didManagerCreate({
        provider: 'did:ebsi',
        options: {
          id,
          privateKeyHex,
          bearer: process.env.EBSI_BEARER,
          hashType: 'sha256',
          keyType: 'Secp256k1',
        },
      })
      expect(identifier.provider).toEqual('did:ebsi')
      expect(identifier.controllerKeyId).toEqual(identifier.keys[0].kid)
    })

    it('should create did:ebsi identifier from provided private key, identifier id, and key type secp256k1 (DID already registered)', async () => {
      identifier = await agent.didManagerCreate({
        provider: 'did:ebsi',
        options: {
          id: '27ca548e74bd14275251623cea1ff0c5',
          privateKeyHex: '2658053a899091ceb000e0f13d0a47790397e0ebc84e2b6a90489430cb6b9e06',
          keyType: 'Secp256k1',
        },
      })
      expect(identifier.provider).toEqual('did:ebsi')
      expect(identifier.controllerKeyId).toEqual(identifier.keys[0].kid)
      expect(identifier.did).toEqual('did:ebsi:zdXUdLZnw3s5dgBuhFyCxcc')
      expect(identifier.keys[0].type).toEqual('Secp256k1')
    })

    it('should create did:ebsi identifier from provided private key, identifier id, and key type P-256 (DID already registered)', async () => {
      identifier = await agent.didManagerCreate({
        provider: 'did:ebsi',
        options: {
          id: '9f3fa87a46b0c03fe6dfeda7fcea220a',
          privateKeyHex: '83828541f41c2760b75ee04b600fc8999641a2944f67f708b4d64000c552bb81',
          keyType: 'P-256',
        },
      })
      expect(identifier.provider).toEqual('did:ebsi')
      expect(identifier.controllerKeyId).toEqual(identifier.keys[0].kid)
      expect(identifier.did).toEqual('did:ebsi:ztH3jgzdkcwRpYVvX9ZToeZ')
      expect(identifier.keys[0].type).toEqual('Secp256r1')
    })

    it('should throw error for trying to create did:ebsi identifier from provided private key, identifier id and wrong key type (Secp256k1)', async () => {
      await expect(
        agent.didManagerCreate({
          provider: 'did:ebsi',
          options: {
            id: '9f3fa87a46b0c03fe6dfeda7fcea220a',
            privateKeyHex: '83828541f41c2760b75ee04b600fc8999641a2944f67f708b4d64000c552bb81',
            keyType: 'Secp256k1',
          },
        }),
      ).rejects.toThrow(
        "did:ebsi:ztH3jgzdkcwRpYVvX9ZToeZ#Lj3WT0OglDJpgAGOMxsFF15SXR6jhyi4dWGgNUgqBZQ does not match any key id in resolved did doc's verification method, check provided crv: Secp256k1",
      )
    })

    it('should throw error for trying to create did:ebsi identifier from provided private key, identifier id and wrong key type (P-256)', async () => {
      await expect(
        agent.didManagerCreate({
          provider: 'did:ebsi',
          options: {
            id: '27ca548e74bd14275251623cea1ff0c5',
            privateKeyHex: '2658053a899091ceb000e0f13d0a47790397e0ebc84e2b6a90489430cb6b9e06',
            keyType: 'P-256',
          },
        }),
      ).rejects.toThrow(
        "did:ebsi:zdXUdLZnw3s5dgBuhFyCxcc#wfd7Q0oKUxkN9Jee4DoM41da98jLORL3GxidNSnaWMo does not match any key id in resolved did doc's verification method, check provided crv: P-256",
      )
    })

    it('should throw error trying to onboard did:ebsi using expired bearer token', async () => {
      await expect(
        agent.didManagerCreate({
          provider: 'did:ebsi',
          options: {
            bearer:
              'eyJhbGciOiJFUzI1NksiLCJ0eXAiOiJKV1QiLCJraWQiOiJkaWQ6ZWJzaTp6cjJyV0RISHJVQ2RaQVc3d3NTYjVuUSNrZXlzLTEifQ.eyJvbmJvYXJkaW5nIjoicmVjYXB0Y2hhIiwidmFsaWRhdGVkSW5mbyI6eyJzdWNjZXNzIjp0cnVlLCJjaGFsbGVuZ2VfdHMiOiIyMDIzLTAzLTIwVDE2OjQ5OjUxWiIsImhvc3RuYW1lIjoiYXBwLXBpbG90LmVic2kuZXUiLCJzY29yZSI6MC45LCJhY3Rpb24iOiJsb2dpbiJ9LCJpc3MiOiJkaWQ6ZWJzaTp6cjJyV0RISHJVQ2RaQVc3d3NTYjVuUSIsImlhdCI6MTY3OTMzMDk5MywiZXhwIjoxNjc5MzMxODkzfQ.W6fIWj5t7hPuVTwa5WGrnyG8-aYLP4OwCSnoPX7fLiL9S9I5xYQfzu0kXXmglsIPtaNzFOOIx2C8jIIxlp0xMw', // Ebsi bearer should be set as environment variable
          },
        }),
      ).rejects.toThrow(
        '{\n  "title": "Unauthorized",\n  "status": 401,\n  "type": "about:blank",\n  "detail": "\\"exp\\" claim timestamp check failed"\n}',
      )
    })

    it('should throw error for providing private key hex without id parameter trying to create did:ebsi', async () => {
      await expect(
        agent.didManagerCreate({
          provider: 'did:ebsi',
          options: {
            privateKeyHex: 'f3157fbbb356a0d56a84a1a9752f81d0638cce4153168bd1b46f68a6e62b82b0',
          },
        }),
      ).rejects.toThrow('Currently, subject identifier id should be provided along with a private key')
    })

    it('should throw error for providing too short private key hex trying to create did:ebsi', async () => {
      await expect(
        agent.didManagerCreate({
          provider: 'did:ebsi',
          options: {
            privateKeyHex: '1234',
            id: '27ca548e74bd14275251623cea1ff0c5',
          },
        }),
      ).rejects.toThrow('Private key should be 32 bytes (64 characters in hex string) long')
    })

    it('should throw error for providing too short id trying to create did:ebsi', async () => {
      await expect(
        agent.didManagerCreate({
          provider: 'did:ebsi',
          options: {
            id: '1234',
          },
        }),
      ).rejects.toThrow(
        'Subject identifier should be 16 bytes (32 characters in hex string, or Uint8Array) long',
      )
    })

    it('should throw error for providing unsupported key type for did:ebsi', async () => {
      await expect(
        agent.didManagerCreate({
          provider: 'did:ebsi',
          options: {
            keyType: 'xyz',
          },
        }),
      ).rejects.toThrow('Unsupported key type, currently only supported Secp256k1 and P-256')
    })

    it('should throw error for providing unsupported hash type for did:ebsi', async () => {
      await expect(
        agent.didManagerCreate({
          provider: 'did:ebsi',
          options: {
            hashType: 'xyz',
          },
        }),
      ).rejects.toThrow('Currently, only sha256 hash type is supported')
    })

    it('should throw error for not providing bearer token for did:ebsi onboarding process', async () => {
      await expect(
        agent.didManagerCreate({
          provider: 'did:ebsi',
          options: {},
        }),
      ).rejects.toThrow('Bearer token is required for onboarding, it should be passed as options parameter')
    })

    it('should throw error for existing alias provider combo', async () => {
      await expect(
        agent.didManagerCreate({
          provider: 'did:web',
          alias: 'example.com',
        }),
      ).rejects.toThrow('Identifier with alias: example.com, provider: did:web already exists')
    })

    it('should get identifier', async () => {
      const identifier2 = await agent.didManagerGet({
        did: identifier.did,
      })
      expect(identifier2.did).toEqual(identifier.did)
    })

    it('should throw error for non existing did', async () => {
      await expect(
        agent.didManagerGet({
          did: 'did:web:foobar',
        }),
      ).rejects.toThrow('Identifier not found')
    })

    it('should get or create identifier', async () => {
      const identifier3 = await agent.didManagerGetOrCreate({
        alias: 'alice',
        provider: 'did:ethr:goerli',
      })

      const identifier4 = await agent.didManagerGetOrCreate({
        alias: 'alice',
        provider: 'did:ethr:goerli',
      })

      expect(identifier3).toEqual(identifier4)

      const identifierKey1 = await agent.didManagerGetOrCreate({
        alias: 'carol',
        provider: 'did:key',
      })

      const identifierKey2 = await agent.didManagerGetOrCreate({
        alias: 'carol',
        provider: 'did:key',
      })

      expect(identifierKey1).toEqual(identifierKey2)

      const identifier5 = await agent.didManagerGetOrCreate({
        alias: 'alice',
        provider: 'did:ethr',
      })

      expect(identifier5).not.toEqual(identifier4)

      const identifier6 = await agent.didManagerGetByAlias({
        alias: 'alice',
        provider: 'did:ethr',
      })

      expect(identifier6).toEqual(identifier5)

      const identifier7 = await agent.didManagerGetByAlias({
        alias: 'alice',
        // default provider is 'did:ethr:goerli'
      })

      expect(identifier7).toEqual(identifier4)
    })

    it('should get identifiers', async () => {
      const allIdentifiers = await agent.didManagerFind()
      expect(allIdentifiers.length).toBeGreaterThanOrEqual(5)

      const aliceIdentifiers = await agent.didManagerFind({
        alias: 'alice',
      })
      expect(aliceIdentifiers.length).toEqual(2)

      const goerliIdentifiers = await agent.didManagerFind({
        provider: 'did:ethr:goerli',
      })
      expect(goerliIdentifiers.length).toBeGreaterThanOrEqual(1)

      // Default provider 'did:ethr:goerli'
      await agent.didManagerCreate({ provider: 'did:ethr:goerli' })

      const goerliIdentifiers2 = await agent.didManagerFind({
        provider: 'did:ethr:goerli',
      })
      expect(goerliIdentifiers2.length).toEqual(goerliIdentifiers.length + 1)
    })

    it('should delete identifier', async () => {
      const allIdentifiers = await agent.didManagerFind()
      const count = allIdentifiers.length

      const result = await agent.didManagerDelete({
        did: allIdentifiers[0].did,
      })

      expect(result).toEqual(true)

      const allIdentifiers2 = await agent.didManagerFind()
      expect(allIdentifiers2.length).toEqual(count - 1)

      await expect(
        agent.didManagerGet({
          did: allIdentifiers[0].did,
        }),
      ).rejects.toThrow('Identifier not found')
    })

    it('should add service to identifier', async () => {
      const webIdentifier = await agent.didManagerGetOrCreate({
        alias: 'foobar.com',
        provider: 'did:web',
      })

      expect(webIdentifier.services.length).toEqual(0)

      const result = await agent.didManagerAddService({
        did: webIdentifier.did,
        service: {
          id: 'did:web:foobar.com#msg',
          type: 'Messaging',
          serviceEndpoint: 'https://foobar.com/messaging',
          description: 'Handles incoming messages',
        },
      })
      expect(result).toEqual({ success: true })

      const webIdentifier2 = await agent.didManagerGetOrCreate({
        alias: 'foobar.com',
        provider: 'did:web',
      })

      expect(webIdentifier2.services.length).toEqual(1)
      expect(webIdentifier2.services[0]).toEqual({
        id: 'did:web:foobar.com#msg',
        type: 'Messaging',
        serviceEndpoint: 'https://foobar.com/messaging',
        description: 'Handles incoming messages',
      })
    })

    it('should remove service from identifier', async () => {
      const result = await agent.didManagerRemoveService({
        did: 'did:web:foobar.com',
        id: 'did:web:foobar.com#msg',
      })

      expect(result).toEqual({ success: true })

      const webIdentifier = await agent.didManagerGetOrCreate({
        alias: 'foobar.com',
        provider: 'did:web',
      })

      expect(webIdentifier.services.length).toEqual(0)
    })

    it('should add key to identifier', async () => {
      const webIdentifier = await agent.didManagerGetOrCreate({
        alias: 'foobar.com',
        provider: 'did:web',
      })

      expect(webIdentifier.keys.length).toEqual(1)

      const newKey = await agent.keyManagerCreate({
        kms: 'local',
        type: 'Secp256k1',
      })

      const result = await agent.didManagerAddKey({
        did: webIdentifier.did,
        key: newKey,
      })

      expect(result).toEqual({ success: true })

      const webIdentifier2 = await agent.didManagerGetOrCreate({
        alias: 'foobar.com',
        provider: 'did:web',
      })

      expect(webIdentifier2.keys.length).toEqual(2)
    })

    it('should remove key from identifier', async () => {
      const webIdentifier = await agent.didManagerGet({
        did: 'did:web:foobar.com',
      })

      expect(webIdentifier.keys.length).toEqual(2)

      const result = await agent.didManagerRemoveKey({
        did: 'did:web:foobar.com',
        kid: webIdentifier.keys[1].kid,
      })

      expect(result).toEqual({ success: true })

      const webIdentifier2 = await agent.didManagerGet({
        did: 'did:web:foobar.com',
      })

      expect(webIdentifier2.keys.length).toEqual(1)
      expect(webIdentifier2.keys[0].kid).toEqual(webIdentifier.keys[0].kid)
    })

    it('should import identifier', async () => {
      expect.assertions(1)
      const did = 'did:web:imported.example'
      const imported = await agent.didManagerImport({
        did,
        provider: 'did:web',
        services: [
          {
            id: `${did}#msg`,
            type: 'Messaging',
            serviceEndpoint: 'https://example.org/messaging',
            description: 'Handles incoming messages',
          },
        ],
        keys: [
          {
            kms: 'local',
            privateKeyHex: 'e63886b5ba367dc2aff9acea6d955ee7c39115f12eaf2aa6b1a2eaa852036668',
            type: 'Secp256k1',
          },
        ],
      })
      expect(imported).toEqual({
        did,
        keys: [
          {
            kid: '04dd467afb12bdb797303e7f3f0c8cd0ba80d518dc4e339e0e2eb8f2d99a9415cac537854a30d31a854b7af0b4fcb54c3954047390fa9500d3cc2e15a3e09017bb',
            kms: 'local',
            meta: {
              algorithms: [
                'ES256K',
                'ES256K-R',
                'eth_signTransaction',
                'eth_signTypedData',
                'eth_signMessage',
                'eth_rawSign',
              ],
            },
            publicKeyHex:
              '04dd467afb12bdb797303e7f3f0c8cd0ba80d518dc4e339e0e2eb8f2d99a9415cac537854a30d31a854b7af0b4fcb54c3954047390fa9500d3cc2e15a3e09017bb',
            type: 'Secp256k1',
          },
        ],
        provider: 'did:web',
        services: [
          {
            description: 'Handles incoming messages',
            id: `${did}#msg`,
            serviceEndpoint: 'https://example.org/messaging',
            type: 'Messaging',
          },
        ],
      })
    })

    it('should set alias for identifier', async () => {
      const identifier = await agent.didManagerCreate()
      const result = await agent.didManagerSetAlias({
        did: identifier.did,
        alias: 'dave',
      })
      expect(result).toEqual(true)

      const identifier2 = await agent.didManagerGetByAlias({
        alias: 'dave',
      })

      expect(identifier2).toEqual({ ...identifier, alias: 'dave' })
    })
  })
}
