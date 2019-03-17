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
			const jwtSecret = 'EMsBfLSNzxcxOxtUeBaaDhTJmBbkLqU247WfcWtX9LPdoaXzHI2YJYhkjRLqzFM/BME='
			const pwdSecret = 'EMsBfLSNzxcxOxtUeBaaDhTJmBbkLqU247WfcWtX9LPdoaXzHI2YJYhkjRLcdwcwe4321341qzFM/BME='
			const { jwt } = new Encryption({ jwtSecret, pwdSecret })
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
			const jwtSecret = 'EMsBfLSNzxcxOxtUeBaaDhTJmBbkLqU247WfcWtX9LPdoaXzHI2YJYhkjRLqzFM/BME='
			const pwdSecret = 'EMsBfLSNzxcxOxtUeBaaDhTJmBbkLqU247WfcWtX9LPdoaXzHI2YJYhkjRLcdwcwe4321341qzFM/BME='
			const { jwt } = new Encryption({ jwtSecret, pwdSecret })
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
			const jwtSecret = 'EMsBfLSNzxcxOxtUeBaaDhTJmBbkLqU247WfcWtX9LPdoaXzHI2YJYhkjRLqzFM/BME='
			const pwdSecret = 'EMsBfLSNzxcxOxtUeBaaDhTJmBbkLqU247WfcWtX9LPdoaXzHI2YJYhkjRLcdwcwe4321341qzFM/BME='
			const jwtSecret2 = 'xQnxPYgc9TfYj10zbZP0zz49rDgbzSde833LqwD9NK19VLgm4EgzyIywqbxb+KLDoW4='
			const pwdSecret2 = 'EMsBfLSNzxcxOxtUeBaaDhTJmBbkLqU247WfcWtX9LPdoaXzHI2YJYcwcwdcwhkjRLcdwcwe4321341qzFM/BME='
			const { jwt } = new Encryption({ jwtSecret, pwdSecret })
			const { jwt:jwt2 } = new Encryption({ jwtSecret: jwtSecret2, pwdSecret:pwdSecret2 })
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
			const jwtSecret = 'EMsBfLSNzxcxOxtUeBaaDhTJmBbkLqU247WfcWtX9LPdoaXzHI2YJYhkjRLqzFM/BME='
			const pwdSecret = 'EMsBfLSNzxcxOxtUeBaaDhTJmBbkLqU247WfcWtX9LPdoaXzHI2YJYhkjRLcdwcwe4321341qzFM/BME='
			const { pwd } = new Encryption({ jwtSecret, pwdSecret })
			const password = 'helloSuper$ecured2019'
			const method = 'sha512'
			const { salt, encryptedPassword } = pwd.encrypt({ password, method })
			
			assert.strictEqual(pwd.validate({ password, encryptedPassword, salt, method }), true, '01')
			assert.notEqual(pwd.validate({ password:'123', encryptedPassword, salt, method }), true, '02')
			done()
		})
	})

	describe('#apiKeyHandler', () => {
		it('01 - Should accept HTTP requests from clients passing the correct API key.', done => {
			const jwtSecret = 'EMsBfLSNzxcxOxtUeBaaDhTJmBbkLqU247WfcWtX9LPdoaXzHI2YJYhkjRLqzFM/BME='
			const pwdSecret = 'EMsBfLSNzxcxOxtUeBaaDhTJmBbkLqU247WfcWtX9LPdoaXzHI2YJYhkjRLcdwcwe4321341qzFM/BME='
			
			const apiKey = 'x-api-key'
			const apiKeyValue = '1234'
			const req = { headers: { 'x-api-key': apiKeyValue } }
			let response = 'OKKKKK'
			const res = { status: code => ({ send: data => { response = { status:code, data } } }) }
			
			const { apiKeyHandler } = new Encryption({ jwtSecret, pwdSecret })

			const handler = apiKeyHandler({ key:apiKey, value:apiKeyValue })

			new Promise(next => handler(req,res,next)).then(() => {
				assert.equal(response, 'OKKKKK', '01')
				done()
			}).catch(done)
		})
		it('02 - Should refuse HTTP requests from clients missing an API key.', done => {
			const jwtSecret = 'EMsBfLSNzxcxOxtUeBaaDhTJmBbkLqU247WfcWtX9LPdoaXzHI2YJYhkjRLqzFM/BME='
			const pwdSecret = 'EMsBfLSNzxcxOxtUeBaaDhTJmBbkLqU247WfcWtX9LPdoaXzHI2YJYhkjRLcdwcwe4321341qzFM/BME='
			
			const apiKey = 'x-api-key'
			const apiKeyValue = '1234'
			const req = { headers: {} }
			let response = 'OKKKKK'
			const res = { status: code => ({ send: data => { response = { status:code, data } } }) }
			
			const { apiKeyHandler } = new Encryption({ jwtSecret, pwdSecret })

			const handler = apiKeyHandler({ key:apiKey, value:apiKeyValue })

			new Promise(next => handler(req,res,next)).then(() => {
				assert.equal(response.status, 403, '01')
				assert.equal(response.data, 'Unauthorized access. Missing API key. Header \'x-api-key\' not found.', '02')
				done()
			}).catch(done)
		})
		it('03 - Should refuse HTTP requests from clients with invalid API key.', done => {
			const jwtSecret = 'EMsBfLSNzxcxOxtUeBaaDhTJmBbkLqU247WfcWtX9LPdoaXzHI2YJYhkjRLqzFM/BME='
			const pwdSecret = 'EMsBfLSNzxcxOxtUeBaaDhTJmBbkLqU247WfcWtX9LPdoaXzHI2YJYhkjRLcdwcwe4321341qzFM/BME='
			
			const apiKey = 'x-api-key'
			const apiKeyValue = '1234'
			const req = { headers: { 'x-api-key': '5678' } }
			let response = 'OKKKKK'
			const res = { status: code => ({ send: data => { response = { status:code, data } } }) }
			
			const { apiKeyHandler } = new Encryption({ jwtSecret, pwdSecret })

			const handler = apiKeyHandler({ key:apiKey, value:apiKeyValue })

			new Promise(next => handler(req,res,next)).then(() => {
				assert.equal(response.status, 403, '01')
				assert.equal(response.data, 'Unauthorized access. Invalid API key \'x-api-key\'.', '02')
				done()
			}).catch(done)
		})
	})

	describe('#bearerHandler', () => {
		it('01 - Should accept HTTP requests from clients passing the correct bearer token.', done => {
			const jwtSecret = 'EMsBfLSNzxcxOxtUeBaaDhTJmBbkLqU247WfcWtX9LPdoaXzHI2YJYhkjRLqzFM/BME='
			const pwdSecret = 'EMsBfLSNzxcxOxtUeBaaDhTJmBbkLqU247WfcWtX9LPdoaXzHI2YJYhkjRLcdwcwe4321341qzFM/BME='
			const { bearerHandler, jwt } = new Encryption({ jwtSecret, pwdSecret })
			
			const user = { id:1, email: 'nic@neap.co' }

			jwt.create(user).then(token => {
				const tokenKey = 'x-bearer-key'
				const req = { headers: { 'x-bearer-key': `bearer ${token}` } }
				let response = 'OKKKKK'
				const res = { status: code => ({ send: data => { response = { status:code, data } } }) }
				
				const handler = bearerHandler({ key:tokenKey })

				new Promise(next => handler(req,res,next)).then(() => {
					assert.equal(response, 'OKKKKK', '01')
					assert.isOk(req.user, '02')
					assert.equal(req.user.id, user.id, '03')
					assert.equal(req.user.email, user.email, '04')
					done()
				}).catch(done)
			})
		})
		it('02 - Should refuse HTTP requests from clients passing the incorrect bearer token.', done => {
			const jwtSecret = 'EMsBfLSNzxcxOxtUeBaaDhTJmBbkLqU247WfcWtX9LPdoaXzHI2YJYhkjRLqzFM/BME='
			const pwdSecret = 'EMsBfLSNzxcxOxtUeBaaDhTJmBbkLqU247WfcWtX9LPdoaXzHI2YJYhkjRLcdwcwe4321341qzFM/BME='
			const { bearerHandler, jwt } = new Encryption({ jwtSecret, pwdSecret })
			
			const user = { id:1, email: 'nic@neap.co' }

			jwt.create(user).then(token => {
				const tokenKey = 'x-bearer-key'
				const req = { headers: { 'x-bearer-key': token } }
				let response = 'OKKKKK'
				const res = { status: code => ({ send: data => { response = { status:code, data } } }) }
				
				const handler = bearerHandler({ key:tokenKey })

				new Promise(next => handler(req,res,next)).then(() => {
					assert.equal(response.status, 403, '01')
					assert.isNotOk(req.user, '02')
					assert.equal(response.data, 'Unauthorized access. Malformed bearer token. Missing bearer schema.', '03')
					done()
				}).catch(done)
			})
		})
		it('03 - Should refuse HTTP requests from clients missing an bearer token.', done => {
			const jwtSecret = 'EMsBfLSNzxcxOxtUeBaaDhTJmBbkLqU247WfcWtX9LPdoaXzHI2YJYhkjRLqzFM/BME='
			const pwdSecret = 'EMsBfLSNzxcxOxtUeBaaDhTJmBbkLqU247WfcWtX9LPdoaXzHI2YJYhkjRLcdwcwe4321341qzFM/BME='
			const { bearerHandler, jwt } = new Encryption({ jwtSecret, pwdSecret })
			
			const user = { id:1, email: 'nic@neap.co' }

			jwt.create(user).then(() => {
				const tokenKey = 'x-bearer-key'
				const req = { headers: {} }
				let response = 'OKKKKK'
				const res = { status: code => ({ send: data => { response = { status:code, data } } }) }
				
				const handler = bearerHandler({ key:tokenKey })

				new Promise(next => handler(req,res,next)).then(() => {
					assert.equal(response.status, 403, '01')
					assert.isNotOk(req.user, '02')
					assert.equal(response.data, 'Unauthorized access. Missing bearer token. Header \'x-bearer-key\' not found.', '03')
					done()
				}).catch(done)
			})
		})
		it('04 - Should refuse HTTP requests from clients with invalid bearer token.', done => {
			const jwtSecret = 'EMsBfLSNzxcxOxtUeBaaDhTJmBbkLqU247WfcWtX9LPdoaXzHI2YJYhkjRLqzFM/BME='
			const jwtSecret2 = 'EMsBfLSNzxcxOxtUeBaaDhTJmBbkLqU247WfcWtX9LPdoaXzHI2YJYhkjRLqzFde2d2d2/BME='
			const pwdSecret2 = 'EMsBfLSNzxcxce3f32f2OxtUeBaaDhTJmBbkLqU247WfcWtX9LPdoaXzHI2YJYhkjRLqzFde2d2d2/BME='
			const { bearerHandler } = new Encryption({ jwtSecret })
			const { jwt:jwt2 } = new Encryption({ jwtSecret: jwtSecret2, pwdSecret:pwdSecret2 })
			
			const user = { id:1, email: 'nic@neap.co' }

			jwt2.create(user).then(token => {
				const tokenKey = 'x-bearer-key'
				const req = { headers: { 'x-bearer-key': `bearer ${token}` } }
				let response = 'OKKKKK'
				const res = { status: code => ({ send: data => { response = { status:code, data } } }) }
				
				const handler = bearerHandler({ key:tokenKey })

				new Promise(next => handler(req,res,next)).then(() => {
					assert.equal(response.status, 403, '01')
					assert.isNotOk(req.user, '02')
					assert.equal(response.data, 'Unauthorized access. Invalid bearer token. invalid signature', '03')
					done()
				}).catch(done)
			})
		})
	})
})









