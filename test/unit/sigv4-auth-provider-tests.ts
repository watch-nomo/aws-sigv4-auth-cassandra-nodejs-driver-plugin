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

import { assert } from 'chai'
import { SigV4AuthProvider, SigV4Authenticator } from '../../lib/sigv4-auth-provider'
import type { AwsCredentialIdentity, AwsCredentialIdentityProvider } from '@smithy/types'

describe('SigV4AuthProvider', () => {
  describe('#extractNonce()', () => {
    let expected = '0c0b0c6f3946d14ce1a49a8f8c86a888'

    it('should pull basic nonce=', function () {
      let buf = Buffer.from('nonce=0c0b0c6f3946d14ce1a49a8f8c86a888')
      assert.equal(SigV4AuthProvider.extractNonce(buf), expected)
    })

    it('should stop at a comma', function () {
      let buf = Buffer.from('nonce=0c0b0c6f3946d14ce1a49a8f8c86a888,,')

      assert.equal(SigV4AuthProvider.extractNonce(buf), expected)
    })

    it('should return undefined when no nonce= is present', function () {
      let buf = Buffer.from('0b0c6f3946d14ce1a49a8f8c86a888,,')

      assert.isUndefined(SigV4AuthProvider.extractNonce(buf))
    })
  })

  describe('#constructor()', () => {
    let originalFn = SigV4AuthProvider.getRegionFromEnv
    let regionFromEnv: string | undefined

    beforeEach(function () {
      regionFromEnv = 'ENV_DEFAULT_REGION'
      SigV4AuthProvider.getRegionFromEnv = () => regionFromEnv
    })

    afterEach(function () {
      SigV4AuthProvider.getRegionFromEnv = originalFn
    })

    it('should use region if provided', () => {
      let provider = new SigV4AuthProvider({ region: 'us-east-23', accessKeyId: 'key' })

      assert.equal(provider.region, 'us-east-23')
    })

    it('should fall back to env region if none provided', () => {
      let provider = new SigV4AuthProvider({ accessKeyId: 'key' })

      assert.equal(provider.region, 'ENV_DEFAULT_REGION')
    })

    it('should fail if no region retrievable', () => {
      regionFromEnv = undefined

      assert.throws(() => {
        new SigV4AuthProvider()
      }, /SIGV4_MISSING_REGION/)
    })

    it('should create a static credential provider when accessKeyId is provided', async () => {
      const options = {
        region: 'us-east-23',
        accessKeyId: 'UserID-1',
        secretAccessKey: 'UserSecretKey-1',
        sessionToken: 'SessionToken-1',
      }
      const provider = new SigV4AuthProvider(options)

      assert.isFunction(provider.chain)
      const creds = await provider.chain()
      assert.equal(creds.accessKeyId, 'UserID-1')
      assert.equal(creds.secretAccessKey, 'UserSecretKey-1')
      assert.equal(creds.sessionToken, 'SessionToken-1')
    })

    it('should create a default credential provider when no accessKeyId is provided', () => {
      const provider = new SigV4AuthProvider({ region: 'us-east-23' })

      assert.isFunction(provider.chain)
    })
  })
})

describe('SigV4Authenticator', () => {
  describe('#initialResponse()', () => {
    const target = new SigV4AuthProvider({ region: 'region', accessKeyId: 'key' }).newAuthenticator()

    it('should call callback function with SigV4 buffer', () => {
      target.initialResponse((err: Error, buf: Buffer) => {
        assert.isNull(err)
        assert.deepEqual(buf, Buffer.from('SigV4\0\0', 'utf8'))
      })
    })
  })

  describe('#evaluateChallenge()', () => {
    const credentialProvider: AwsCredentialIdentityProvider = async () => ({
      accessKeyId: 'UserID-1',
      secretAccessKey: 'UserSecretKey-1',
      sessionToken: 'SessiosnToken-1',
    })

    const target = new SigV4Authenticator({
      region: 'us-west-2',
      chain: credentialProvider,
      date: new Date(1591742511000),
    })

    it('should call callback with signed request', async () => {
      const nonceBuffer = Buffer.from('nonce=91703fdc2ef562e19fbdab0f58e42fe5')
      const expected =
        'signature=7f3691c18a81b8ce7457699effbfae5b09b4e0714ab38c1292dbdf082c9ddd87,access_key=UserID-1,amzdate=2020-06-09T22:41:51.000Z,session_token=SessiosnToken-1'

      await new Promise<void>((resolve) => {
        target.evaluateChallenge(nonceBuffer, (err: Error, buf: Buffer) => {
          assert.isNull(err)
          assert.equal(buf.toString(), expected)
          resolve()
        })
      })
    })

    it('should fail when nonce is not found', () => {
      const nonceBuffer = Buffer.from('buffer1')
      const expected = 'Error: [SIGV4_MISSING_NONCE] Did not find nonce in SigV4 challenge:[buffer1]'

      let calledCallback = false
      target.evaluateChallenge(nonceBuffer, (err: Error, buf: Buffer) => {
        assert.equal(err.toString(), expected)
        calledCallback = true
      })
      assert.isTrue(calledCallback)
    })
  })
})
