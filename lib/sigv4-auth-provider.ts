/*
 *   Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 *   Licensed under the Apache License, Version 2.0 (the "License").
 *   You may not use this file except in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing, software
 *   distributed under the License is distributed on an "AS IS" BASIS,
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *   See the License for the specific language governing permissions and
 *   limitations under the License.
 */

'use strict'
import cass, { auth } from 'cassandra-driver'
import { computeSigV4SignatureCassandraRequest } from './sigv4-auth-signature'
import { fromNodeProviderChain } from '@aws-sdk/credential-providers'
import { AwsCredentialIdentityProvider } from '@smithy/types'

// The cassandra-driver type definitions declare AuthProvider and Authenticator
// as interfaces, but at runtime they are constructor functions. We need to
// extend them (not just implement) so that instanceof checks in the driver pass.
// eslint-disable-next-line @typescript-eslint/no-require-imports
const { AuthProvider: AuthProviderBase, Authenticator: AuthenticatorBase } =
  require('cassandra-driver/lib/auth/provider') as {
    AuthProvider: new () => auth.AuthProvider
    Authenticator: new () => auth.Authenticator
  }

/**
 * Creates a new instance of the Authenticator provider.
 *
 * @classdesc Provides an SigV4 [Authenticator]{@link cass.auth.AuthProvider} instances to be used when
 * connecting to a host.
 * @extends cass.auth.AuthProvider
 * @param {object} options
 * @param {string} options.region - aws region such as 'us-west-2'.
 * @param {string} options.accessKeyId - if not provided default to using profile
 * @param {string} options.secretAccessKey - AWS profile iff accessKeyId is not provided.
 * @param {string} options.sessionToken - use this if you are using temporary credentials.
 * @constructor
 */

export class SigV4AuthProvider extends AuthProviderBase {
  region: string
  chain: AwsCredentialIdentityProvider
  constructor(credentials?: {
    region?: string
    accessKeyId?: string
    secretAccessKey?: string
    sessionToken?: string
  }) {
    super()
    const accessKeyId = credentials?.accessKeyId
    const secretAccessKey = credentials?.secretAccessKey
    this.chain =
      accessKeyId && secretAccessKey
        ? async () => ({ ...credentials, accessKeyId, secretAccessKey })
        : fromNodeProviderChain()
    const region = credentials?.region ?? SigV4AuthProvider.getRegionFromEnv()
    if (!region) {
      throw new Error(
        '[SIGV4_MISSING_REGION] No region provided.  You must either provide a region or set ' +
          'environment variable [AWS_REGION]'
      )
    }
    this.region = region
  }

  static getRegionFromEnv() {
    return process.env.AWS_REGION
  }

  static extractNonce(buf: Buffer): string | undefined {
    let bufAsString = buf.toString()

    let res1 = bufAsString.split('nonce=')

    if (res1.length < 2) {
      return undefined
    }

    let res2 = res1[1].split(',')

    return res2[0]
  }

  newAuthenticator(): auth.Authenticator {
    return new SigV4Authenticator({
      region: this.region,
      chain: this.chain,
    })
  }
}

/**
 * Creates a new instance of the Authenticator for SigV4.
 *
 * Generally speaking you should avoid constructing this directly, and instead
 * really on {@link SigV4AuthProvider} newAuthenticator method
 *
 * @classdesc allows SigV4 to be used as an authentication method.
 * @extends cass.auth.Authenticator
 * @param {object} options
 * @param {string} options.region - aws region such as 'us-west-2'.
 * @param {AWS.CredentialProviderChain} options.chain - provider chain with appropriate credentials
 * @param {Date} options.date - fixed date to use.  If not provided, we use current date.
 * @constructor
 */

export class SigV4Authenticator extends AuthenticatorBase {
  region: string
  chain: AwsCredentialIdentityProvider
  date?: Date
  constructor({ region, chain, date }: { region: string; chain: AwsCredentialIdentityProvider; date?: Date }) {
    super()
    this.region = region
    this.chain = chain
    this.date = date
  }

  initialResponse(callback: Function) {
    // we need to tell the system we want sigV4.
    const responseBuffer = Buffer.from('SigV4\0\0', 'utf8')
    callback(null, responseBuffer)
  }

  evaluateChallenge(challenge: Buffer, callback: Function) {
    let nonce = SigV4AuthProvider.extractNonce(challenge)
    if (!nonce) {
      callback(new Error(`[SIGV4_MISSING_NONCE] Did not find nonce in SigV4 challenge:[${challenge}]`), null)
      return
    }

    let dateToUse = this.date || new Date()

    this.chain().then((creds) => {
      let signedString = computeSigV4SignatureCassandraRequest({
        region: this.region,
        accessKeyId: creds.accessKeyId,
        secretAccessKey: creds.secretAccessKey,
        sessionToken: creds.sessionToken,
        date: dateToUse,
        nonce: nonce,
      })
      callback(null, Buffer.from(signedString))
    })
  }

  onAuthenticationSuccess(_token?: Buffer) {
    // No-op: SigV4 authentication is complete after evaluateChallenge.
    // The server does not send a final token that requires processing.
  }
}
