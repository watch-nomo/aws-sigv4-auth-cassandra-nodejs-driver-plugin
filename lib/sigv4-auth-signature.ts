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

import crypto from 'node:crypto'

const CASSANDRA_SERVICE_NAME = 'cassandra'
const AWS4_SIGNING_ALGORITHM = 'AWS4-HMAC-SHA256'
const V4_IDENTIFIER = 'aws4_request'

/**
 * Compute the signature from signing key.
 *
 * @param {string} stringToSign - the complete string we must sign
 * @param {Buffer} signingKey - derived from date, region etc
 * @returns {string} hex-encoded signature
 * @private
 */
function computeSignature(stringToSign: string, signingKey: Buffer): string {
  return crypto.createHmac('sha256', signingKey).update(stringToSign).digest('hex')
}

/**
 * Form the authentication string which contains metadata and signature.
 *
 * @param {string} signature - hex-encoded signature
 * @param {string} accessKeyId - Access id of AccessKey pair
 * @param {string} isoDateString - timestamp of form '2020-06-09T22:41:51.000Z'
 * @param {string} sessionToken - session token if temporary credentials
 * @returns {string} full authentication string
 * @private
 */
function formSignedString(
  signature: string,
  accessKeyId: string,
  isoDateString: string,
  sessionToken?: string
): string {
  let result = `signature=${signature},access_key=${accessKeyId},amzdate=${isoDateString}`

  if (sessionToken) {
    result += `,session_token=${sessionToken}`
  }

  return result
}

/**
 * Creates the signing key for signature.
 * This is based on the date and region
 *
 * @param {string} secretAccessKey - key from AccessKey pair
 * @param {string} credentialDateStamp - aws credential stamp, '20200609' for example
 * @param {string} region - the aws region, example 'us-west-2'
 * @returns {Buffer} binary signing key
 * @private
 */
function deriveSigningKey(secretAccessKey: string, credentialDateStamp: string, region: string): Buffer {
  const secret = 'AWS4' + secretAccessKey
  const dateHmac    = crypto.createHmac('sha256', secret).update(credentialDateStamp).digest()
  const regionHmac  = crypto.createHmac('sha256', dateHmac).update(region).digest()
  const serviceHmac = crypto.createHmac('sha256', regionHmac).update(CASSANDRA_SERVICE_NAME).digest()
  return              crypto.createHmac('sha256', serviceHmac).update(V4_IDENTIFIER).digest()
}

/**
 * Transforms a date into an aws credential date stamp.
 *
 * @example 2020-06-09T22:41:51.000Z -> '20200609'
 * @param {Date} date - representing the request time
 * @returns {string} aws credential timestamp
 * @private
 */
function toCredentialDateStamp(date: Date): string {
  return date.toISOString().replace(/[:\-]|\.\d{3}/g, '').substring(0, 8)
}

/**
 * Form the data that will be checked against the signature we build.
 *
 * @param {string} canonicalRequest - the formal request sorted, and made unambiguous
 * @param {string} isoDateString - timestamp of form '2020-06-09T22:41:51.000Z'
 * @param {string} signingScope - description defining the request
 * @returns {string} the string that will be compared against to ensure authentication
 * @private
 */
function createStringToSign(canonicalRequest: string, isoDateString: string, signingScope: string): string {
  const digest = crypto.createHash('sha256').update(canonicalRequest).digest('hex')
  return `${AWS4_SIGNING_ALGORITHM}\n${isoDateString}\n${signingScope}\n${digest}`
}

/**
 * Determines a scope string that is used in the plain text to be signed.
 *
 * @param {string} credentialDateStamp - aws credential stamp, '20200609' for example
 * @param {string} region - aws region such as 'us-west-2'
 * @returns {string} for example '20200609/us-west-2/cassandra/aws4_request'
 * @private
 */
function deriveSigningScope(credentialDateStamp: string, region: string): string {
  return [credentialDateStamp, region, CASSANDRA_SERVICE_NAME, V4_IDENTIFIER].join('/')
}

function formatXAmzCred(accessKeyId: string, scope: string) {
  return `X-Amz-Credential=${accessKeyId}%2F${encodeURIComponent(scope)}`
}

function formatXAmzDate(timestamp: string) {
  return `X-Amz-Date=${encodeURIComponent(timestamp)}`
}

const ADZ_ALGORITHM_HEADER = `X-Amz-Algorithm=${AWS4_SIGNING_ALGORITHM}`
const AMZ_EXPIRES_HEADER = 'X-Amz-Expires=900'

/**
 * Creates the canonical request.  This is a sorted, unambiguous version of
 * the request that will be compared to for authentication.
 *
 * @param {string} accessKeyId - access id of the AccessKey pair
 * @param {string} signingScope - description defining the request
 * @param {string} isoDateString - timestamp of form '2020-06-09T22:41:51.000Z'
 * @param {string} nonceHash - hex-encoded sha256 digest of the nonce
 * @returns {string} the canonical request.
 * @private
 */
function deriveCanonicalRequest(
  accessKeyId: string,
  signingScope: string,
  isoDateString: string,
  nonceHash: string
): string {
  const headers = [
    ADZ_ALGORITHM_HEADER,
    formatXAmzCred(accessKeyId, signingScope),
    formatXAmzDate(isoDateString),
    AMZ_EXPIRES_HEADER,
  ]

  headers.sort()

  const queryString = headers.join('&')

  return `PUT\n/authenticate\n${queryString}\nhost:${CASSANDRA_SERVICE_NAME}\n\nhost\n${nonceHash}`
}

/**
 * Computes the signature line of a given cassandra request.
 *
 * @param {object} options
 * @param {string} options.region - region such as 'us-west-2'
 * @param {string} options.nonce - nonce provided by the challenge request
 * @param {Date} options.date - date representing the time of the request
 * @param {string} options.accessKeyId - access id of the AccessKey pair
 * @param {string} options.secretAccessKey - password/secret of the AccessKey pair
 * @param {string} options.sessionToken - optionally set when access credentials are temporary.
 * @returns {string} a complete signature string.
 * @example
 * // returns
 * // 'signature=7f3691c18a81b8ce7457699effbfae5b09b4e0714ab38c1292dbdf082c9ddd87,access_key=UserID-1,amzdate=2020-06-09T22:41:51.000Z'
 * let response = computeSigV4SignatureCassandraRequest({
 *   region: 'us-west-2',
 *   nonce: '91703fdc2ef562e19fbdab0f58e42fe5',
 *   date: new Date(1591742511000),
 *   accessKeyId: 'UserID-1',
 *   secretAccessKey: 'UserSecretKey-1'
 * });
 */
export function computeSigV4SignatureCassandraRequest({
  region,
  nonce,
  date,
  accessKeyId,
  secretAccessKey,
  sessionToken,
}: {
  region: string
  nonce: string
  date: Date
  accessKeyId: string
  secretAccessKey: string
  sessionToken?: string
}): string {
  const isoDate           = date.toISOString()
  const credentialDateStamp = toCredentialDateStamp(date)
  const nonceHash         = crypto.createHash('sha256').update(nonce).digest('hex')
  const signingScope      = deriveSigningScope(credentialDateStamp, region)
  const canonicalRequest  = deriveCanonicalRequest(accessKeyId, signingScope, isoDate, nonceHash)
  const signingKey        = deriveSigningKey(secretAccessKey, credentialDateStamp, region)
  const stringToSign      = createStringToSign(canonicalRequest, isoDate, signingScope)
  const signature         = computeSignature(stringToSign, signingKey)

  return formSignedString(signature, accessKeyId, isoDate, sessionToken)
}

/**
 * Exposed internals for testing each step of the signing process independently.
 * @private
 */
export const testingOnly = {
  signingSteps: {
    deriveSigningScope,
    deriveCanonicalRequest,
    deriveSigningKey,
    createStringToSign,
    computeSignature,
    formSignedString,
  },
}
