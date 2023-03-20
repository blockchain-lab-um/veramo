export namespace EbsiConfig {
  export const BASE_URL = 'https://api-pilot.ebsi.eu'
  export const DID_REGISTRY = `${BASE_URL}/did-registry/v3/identifiers`
  export const TAR_REG = `${BASE_URL}/trusted-apps-registry/v3/apps`
}

export namespace EbsiEndpoints {
  export const AUTH_RESPONSE = '/users-onboarding/v2/authentication-responses'
  export const SIOP_SESSIONS = '/authorisation/v2/siop-sessions'
  export const DID_REGISTRY_RPC = '/did-registry/v3/jsonrpc'
}
