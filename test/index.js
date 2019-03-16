/**
 * Copyright (c) 2017-2019, Neap Pty Ltd.
 * All rights reserved.
 * 
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
*/

const { assert } = require('chai')
const Encryption = require('../index.js')

describe('Encryption', () => {
	describe('#jwt', () => {
		it('01 - Should create and validate JWT tokens.', done => {
			const appSecret = 'EMsBfLSNzxcxOxtUeBaaDhTJmBbkLqU247WfcWtX9LPdoaXzHI2YJYhkjRLqzFM/BME='
			const { jwt } = new Encryption({ appSecret })
			const claims = {
				id:1,
				email: 'nic@neap.co'
			}

			jwt.create(claims)
				.then(token => jwt.validate(token))
				.then(data => {
					assert.equal(data.id, claims.id, '01')
					assert.equal(data.email, claims.email, '02')
					done()
				})
				.catch(done)
		})
		it('02 - Should create and invalidate malformed JWT tokens.', done => {
			const appSecret = 'EMsBfLSNzxcxOxtUeBaaDhTJmBbkLqU247WfcWtX9LPdoaXzHI2YJYhkjRLqzFM/BME='
			const { jwt } = new Encryption({ appSecret })
			const claims = {
				id:1,
				email: 'nic@neap.co'
			}

			jwt.create(claims)
				.then(() => jwt.validate('123'))
				.then(() => {
					throw new Error('Should have failed')
				})
				.catch(err => {
					assert.equal(err.message, 'jwt malformed', '01')
					done()
				})
				.catch(done)
		})
		it('03 - Should create and invalidate incorrectly signed JWT tokens.', done => {
			const appSecret = 'EMsBfLSNzxcxOxtUeBaaDhTJmBbkLqU247WfcWtX9LPdoaXzHI2YJYhkjRLqzFM/BME='
			const appSecret2 = 'xQnxPYgc9TfYj10zbZP0zz49rDgbzSde833LqwD9NK19VLgm4EgzyIywqbxb+KLDoW4='
			const { jwt } = new Encryption({ appSecret })
			const { jwt:jwt2 } = new Encryption({ appSecret: appSecret2 })
			const claims = {
				id:1,
				email: 'nic@neap.co'
			}

			Promise.all([jwt.create(claims), jwt2.create(claims)])
				.then(([,token]) => jwt.validate(token))
				.then(() => {
					throw new Error('Should have failed')
				})
				.catch(err => {
					assert.equal(err.message, 'invalid signature', '01')
					done()
				})
				.catch(done)
		})
	})


	describe('#pwd', () => {
		it('01 - Should encrypt password.', done => {
			const appSecret = 'EMsBfLSNzxcxOxtUeBaaDhTJmBbkLqU247WfcWtX9LPdoaXzHI2YJYhkjRLqzFM/BME='
			const { pwd } = new Encryption({ appSecret })
			const password = 'helloSuper$ecured2019'
			const method = 'sha512'
			const { salt, encryptedPassword } = pwd.encrypt({ password, method })
			
			assert.strictEqual(pwd.validate({ password, encryptedPassword, salt, method }), true, '01')
			assert.notEqual(pwd.validate({ password:'123', encryptedPassword, salt, method }), true, '02')
			done()
		})
	})
})









