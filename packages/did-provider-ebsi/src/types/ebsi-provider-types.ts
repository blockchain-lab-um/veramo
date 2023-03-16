import { EbsiVerifiablePresentation } from "@cef-ebsi/verifiable-presentation";
import { JWK } from "jose";

export type IRequestVerifiableAuthorizationArgs = {
  /**
   * JWT encoded id token
   */
  idTokenJwt: string;
  /**
   * Bearer token needed for authorization
   */
  bearer: string;
};

export type IVerifiableAuthorization = {
  /**
   * JWT encoded Verifiable Authorization
   */
  verifiableCredential: string;
};

export type IVerifiablePresentation = {
  /**
   * JWT encoded Verifiable Presentation
   */
  jwtVp: string;
  /**
   * Payload of the Verifiable Presentation
   */
  payload: EbsiVerifiablePresentation;
};

export type ISession = {
  /**
   * Encrypted payload with user's public key
   */
  ake1_enc_payload: string;
  /**
   * Encrypted payload with user's public key
   */
  ake1_sig_payload: ISIOPSessionPayload;
  /**
   * Detached JWS of AKE1 Signing Payload
   */
  ake1_jws_detached: string;
  /**
   * API KID
   */
  kid: string;
};

export type IKeyJwks = {
  /**
   * Private key in JWK format
   */
  privateKeyJwk: JWK;
  /**
   * Public key in JWK format
   */
  publicKeyJwk: JWK;
};

export type ISIOPSessionPayload = {
  /**
   * Issued at
   */
  iat: number;
  /**
   * Expires at
   */
  exp: number;
  /**
   * Nonce used during the authentication process
   */
  ake1_nonce: string;
  /**
   * Encrypted payload with user's public key
   */
  ake1_enc_payload: string;
  /**
   * API DID
   */
  did: string;
  /**
   * Issuer
   */
  iss: string;
};

export type IRPCResult = {
  /**
   * Must be exactly "2.0"
   */
  jsonrpc: string;
  /**
   * Same identifier established by the client in the call
   */
  id: number;
  /**
   * Result of the call
   */
  result?: string | object;
  /**
   * Error of the call if raised
   */
  error?: string | object;
};
