/**
 * Copyright (c) 2017-2019, Neap Pty Ltd.
 * All rights reserved.
 * 
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
*/

const { assert } = require('chai')
const crypto = require('crypto')
const Crypto = require('../index.js')
const fs = require('fs')

describe('Crypto', () => {
	describe('#jwt', () => {
		it('01 - Should create and validate JWT tokens.', done => {
			const jwtSecret = 'EMsBfLSNzxcxOxtUeBaaDhTJmBbkLqU247WfcWtX9LPdoaXzHI2YJYhkjRLqzFM/BME='
			const { jwt } = new Crypto()
			jwt.setKey(jwtSecret)
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
			const { jwt } = new Crypto()
			jwt.setKey(jwtSecret)
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
			const jwtSecret2 = 'xQnxPYgc9TfYj10zbZP0zz49rDgbzSde833LqwD9NK19VLgm4EgzyIywqbxb+KLDoW4='
			const { jwt } = new Crypto()
			const { jwt:jwt2 } = new Crypto()
			jwt.setKey(jwtSecret)
			jwt2.setKey(jwtSecret2)
			const claims = {
				id:1,
				email: 'nic@neap.co'
			}

			Promise.all([jwt.create(claims), jwt2.create(claims)])
				.then(([,token]) => {
					return jwt.validate(token)
				})
				.then(() => {
					throw new Error('Should have failed')
				})
				.catch(err => {
					assert.equal(err.message, 'invalid signature', '01')
					done()
				})
				.catch(done)
		})
		it('04 - Should support asymmetric algorithm.', done => {
			const alg = 'ES256'
			const privateKey = fs.readFileSync('./test/key.pem').toString()
			const publicKey = fs.readFileSync('./test/key.pub').toString()
			const { jwt } = new Crypto()
			jwt.setKey(privateKey)
			const claims = {
				id:1,
				email: 'nic@neap.co'
			}

			jwt.create(claims, { algorithm:alg })
				.then(token => {
					return jwt.validate(token, { key:publicKey, algorithms:['ES256'] })
				})
				.then(data => {
					assert.equal(data.id, claims.id, '01')
					assert.equal(data.email, claims.email, '02')
					done()
				})
				.catch(done)
		})
		it('05 - Should support the \'secret\' argument in lieu of \'jwtSecret\'.', done => {
			const secret = 'EMsBfLSNzxcxOxtUeBaaDhTJmBbkLqU247WfcWtX9LPdoaXzHI2YJYhkjRLqzFM/BME='
			const secret2 = 'xQnxPYgc9TfYj10zbZP0zz49rDgbzSde833LqwD9NK19VLgm4EgzyIywqbxb+KLDoW4='
			const { jwt } = new Crypto({ secret })
			const { jwt:jwt2 } = new Crypto({ secret: secret2 })
			const claims = {
				id:1,
				email: 'nic@neap.co'
			}

			Promise.all([jwt.create(claims), jwt2.create(claims)])
				.then(([,token]) => {
					return jwt.validate(token)
				})
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
		it('01 - Should hash and salt password.', done => {
			const { pwd } = new Crypto()
			const password = 'helloSuper$ecured2019'
			const alg = 'md5'
			const { salt, hashedSaltedPassword } = pwd.hashAndSalt({ password, alg })
			
			assert.strictEqual(pwd.validate({ password, hashedSaltedPassword, salt, alg }), true, '01')
			assert.notEqual(pwd.validate({ password:'123', hashedSaltedPassword, salt, alg }), true, '02')
			done()
		})
	})

	describe('#encryption', () => {
		it('01 - Should encrypt/decrypt data and default to whatever algorithm is most suitable', () => {
			// This example generates the secrets, but in reality, you would probably 
			// store that key in an environment variable such as process.env.ENCRYPTION_KEY
			const privateKey = crypto.randomBytes(24).toString('base64').slice(0, 32) // this key MUST be a 256 bits key (i.e., 32 characters)
			// console.log({ privateKey })
			const { encryption } = new Crypto({ secret:privateKey })
			const data = { firstName:'Nic', secret:1234 }

			const { cipher, key, encrypted, format } = encryption.encrypt(JSON.stringify(data), { format:'hex' })
			
			const decryptedData= JSON.parse(encryption.decrypt(encrypted, { cipher, key, format }))
			
			assert.strictEqual(data.firstName, decryptedData.firstName, '01')
			assert.strictEqual(data.secret, decryptedData.secret, '02')
			assert.strictEqual(cipher, 'des-ede3', '03')
		})
		it('02 - Should encrypt/decrypt data using AES', () => {
			const { encryption } = new Crypto()
			encryption.aes.setKey()
			encryption.aes.setIv()
			const data = { firstName:'Nic', secret:1234 }

			const { cipher, encrypted } = encryption.aes.encrypt(JSON.stringify(data))
			
			const decryptedData= JSON.parse(encryption.decrypt(encrypted))
			
			assert.strictEqual(data.firstName, decryptedData.firstName, '01')
			assert.strictEqual(data.secret, decryptedData.secret, '02')
			assert.strictEqual(cipher, 'aes-256-cbc', '03')
		})
		it('03 - Should encrypt/decrypt data using Triple DES', () => {
			const { encryption } = new Crypto()
			encryption.des.setKey()
			const data = { firstName:'Nic', secret:1234 }

			const { cipher, encrypted } = encryption.encrypt(JSON.stringify(data))
			
			const decryptedData= JSON.parse(encryption.des.decrypt(encrypted))
			
			assert.strictEqual(data.firstName, decryptedData.firstName, '01')
			assert.strictEqual(data.secret, decryptedData.secret, '02')
			assert.strictEqual(cipher, 'des-ede3', '03')
		})
	})

	describe('#apiKeyHandler', () => {
		it('01 - Should accept HTTP requests from clients passing the correct API key.', done => {
			const jwtSecret = 'EMsBfLSNzxcxOxtUeBaaDhTJmBbkLqU247WfcWtX9LPdoaXzHI2YJYhkjRLqzFM/BME='
			
			const apiKey = 'x-api-key'
			const apiKeyValue = '1234'
			const req = { headers: { 'x-api-key': apiKeyValue } }
			let response = 'OKKKKK'
			const res = { status: code => ({ send: data => { response = { status:code, data } } }) }
			
			const { apiKeyHandler } = new Crypto({ jwtSecret })

			const handler = apiKeyHandler({ key:apiKey, value:apiKeyValue })

			new Promise(next => handler(req,res,next)).then(() => {
				assert.equal(response, 'OKKKKK', '01')
				done()
			}).catch(done)
		})
		it('02 - Should refuse HTTP requests from clients missing an API key.', done => {
			const jwtSecret = 'EMsBfLSNzxcxOxtUeBaaDhTJmBbkLqU247WfcWtX9LPdoaXzHI2YJYhkjRLqzFM/BME='
			
			const apiKey = 'x-api-key'
			const apiKeyValue = '1234'
			const req = { headers: {} }
			let response = 'OKKKKK'
			const res = { status: code => ({ send: data => { response = { status:code, data } } }) }
			
			const { apiKeyHandler } = new Crypto({ jwtSecret })

			const handler = apiKeyHandler({ key:apiKey, value:apiKeyValue })

			new Promise(next => handler(req,res,next)).then(() => {
				assert.equal(response.status, 403, '01')
				assert.equal(response.data, 'Unauthorized access. Missing API key. Header \'x-api-key\' not found.', '02')
				done()
			}).catch(done)
		})
		it('03 - Should refuse HTTP requests from clients with invalid API key.', done => {
			const jwtSecret = 'EMsBfLSNzxcxOxtUeBaaDhTJmBbkLqU247WfcWtX9LPdoaXzHI2YJYhkjRLqzFM/BME='
			
			const apiKey = 'x-api-key'
			const apiKeyValue = '1234'
			const req = { headers: { 'x-api-key': '5678' } }
			let response = 'OKKKKK'
			const res = { status: code => ({ send: data => { response = { status:code, data } } }) }
			
			const { apiKeyHandler } = new Crypto({ jwtSecret })

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
			const { bearerHandler, jwt } = new Crypto({ jwtSecret })
			
			const user = { id:1, email: 'nic@neap.co' }

			jwt.create(user).then(token => {
				const req = { headers: { 'Authorization': `bearer ${token}` } }
				let response = 'OKKKKK'
				const res = { status: code => ({ send: data => { response = { status:code, data } } }) }
				
				const handler = bearerHandler()

				new Promise(next => handler(req,res,next)).then(() => {
					assert.equal(response, 'OKKKKK', '01')
					assert.isOk(req.claims, '02')
					assert.equal(req.claims.id, user.id, '03')
					assert.equal(req.claims.email, user.email, '04')
					done()
				}).catch(done)
			})
		})
		it('02 - Should accept HTTP requests from clients passing the correct bearer token in a custom header.', done => {
			const jwtSecret = 'EMsBfLSNzxcxOxtUeBaaDhTJmBbkLqU247WfcWtX9LPdoaXzHI2YJYhkjRLqzFM/BME='
			const { bearerHandler, jwt } = new Crypto({ jwtSecret })
			
			const user = { id:1, email: 'nic@neap.co' }

			jwt.create(user).then(token => {
				const tokenKey = 'x-bearer-key'
				const req = { headers: { 'x-bearer-key': `bearer ${token}` } }
				let response = 'OKKKKK'
				const res = { status: code => ({ send: data => { response = { status:code, data } } }) }
				
				const handler = bearerHandler({ key:tokenKey })

				new Promise(next => handler(req,res,next)).then(() => {
					assert.equal(response, 'OKKKKK', '01')
					assert.isOk(req.claims, '02')
					assert.equal(req.claims.id, user.id, '03')
					assert.equal(req.claims.email, user.email, '04')
					done()
				}).catch(done)
			})
		})
		it('03 - Should refuse HTTP requests from clients passing the incorrect bearer token.', done => {
			const jwtSecret = 'EMsBfLSNzxcxOxtUeBaaDhTJmBbkLqU247WfcWtX9LPdoaXzHI2YJYhkjRLqzFM/BME='
			const { bearerHandler, jwt } = new Crypto({ jwtSecret })
			
			const user = { id:1, email: 'nic@neap.co' }

			jwt.create(user).then(token => {
				const tokenKey = 'x-bearer-key'
				const req = { headers: { 'x-bearer-key': token } }
				let response = 'OKKKKK'
				const res = { status: code => ({ send: data => { response = { status:code, data } } }) }
				
				const handler = bearerHandler({ key:tokenKey })

				new Promise(next => handler(req,res,next)).then(() => {
					assert.equal(response.status, 403, '01')
					assert.isNotOk(req.claims, '02')
					assert.equal(response.data, 'Unauthorized access. Malformed bearer token. Missing bearer schema.', '03')
					done()
				}).catch(done)
			})
		})
		it('04 - Should refuse HTTP requests from clients missing an bearer token.', done => {
			const jwtSecret = 'EMsBfLSNzxcxOxtUeBaaDhTJmBbkLqU247WfcWtX9LPdoaXzHI2YJYhkjRLqzFM/BME='
			const { bearerHandler, jwt } = new Crypto({ jwtSecret })
			
			const user = { id:1, email: 'nic@neap.co' }

			jwt.create(user).then(() => {
				const tokenKey = 'x-bearer-key'
				const req = { headers: {} }
				let response = 'OKKKKK'
				const res = { status: code => ({ send: data => { response = { status:code, data } } }) }
				
				const handler = bearerHandler({ key:tokenKey })

				new Promise(next => handler(req,res,next)).then(() => {
					assert.equal(response.status, 403, '01')
					assert.isNotOk(req.claims, '02')
					assert.equal(response.data, 'Unauthorized access. Missing bearer token. Header \'x-bearer-key\' not found.', '03')
					done()
				}).catch(done)
			})
		})
		it('05 - Should refuse HTTP requests from clients with invalid bearer token.', done => {
			const jwtSecret = 'EMsBfLSNzxcxOxtUeBaaDhTJmBbkLqU247WfcWtX9LPdoaXzHI2YJYhkjRLqzFM/BME='
			const jwtSecret2 = 'EMsBfLSNzxcxOxtUeBaaDhTJmBbkLqU247WfcWtX9LPdoaXzHI2YJYhkjRLqzFde2d2d2/BME='
			const { bearerHandler } = new Crypto({ jwtSecret })
			const { jwt:jwt2 } = new Crypto({ jwtSecret: jwtSecret2 })
			
			const user = { id:1, email: 'nic@neap.co' }

			jwt2.create(user).then(token => {
				const tokenKey = 'x-bearer-key'
				const req = { headers: { 'x-bearer-key': `bearer ${token}` } }
				let response = 'OKKKKK'
				const res = { status: code => ({ send: data => { response = { status:code, data } } }) }
				
				const handler = bearerHandler({ key:tokenKey })

				new Promise(next => handler(req,res,next)).then(() => {
					assert.equal(response.status, 403, '01')
					assert.isNotOk(req.claims, '02')
					assert.equal(response.data, 'Unauthorized access. Invalid bearer token. invalid signature', '03')
					done()
				}).catch(done)
			})
		})
		it('06 - Should accept HTTP requests from clients passing the correct bearer token in a cookie.', done => {
			const jwtSecret = 'EMsBfLSNzxcxOxtUeBaaDhTJmBbkLqU247WfcWtX9LPdoaXzHI2YJYhkjRLqzFM/BME='
			const { bearerHandler, jwt } = new Crypto({ jwtSecret })
			
			const user = { id:1, email: 'nic@neap.co' }

			jwt.create(user).then(token => {
				const req = { headers: { 'cookie': `hello=${token}` } }
				let response = 'OKKKKK'
				const res = { status: code => ({ send: data => { response = { status:code, data } } }) }
				
				const handler = bearerHandler({ cookie:'hello' })

				new Promise(next => handler(req,res,next)).then(() => {
					assert.equal(response, 'OKKKKK', '01')
					assert.isOk(req.claims, '02')
					assert.equal(req.claims.id, user.id, '03')
					assert.equal(req.claims.email, user.email, '04')
					done()
				}).catch(done)
			})
		})
		it('07 - Should accept HTTP requests from clients passing the correct bearer token in a query parameter.', done => {
			const jwtSecret = 'EMsBfLSNzxcxOxtUeBaaDhTJmBbkLqU247WfcWtX9LPdoaXzHI2YJYhkjRLqzFM/BME='
			const { bearerHandler, jwt } = new Crypto({ jwtSecret })
			
			const user = { id:1, email: 'nic@neap.co' }

			jwt.create(user).then(token => {
				const req = { url:`https://neap.co/oauth2/token?code=${token}` }
				let response = 'OKKKKK'
				const res = { status: code => ({ send: data => { response = { status:code, data } } }) }
				
				const handler = bearerHandler({ query:'code' })

				new Promise(next => handler(req,res,next)).then(() => {
					assert.equal(response, 'OKKKKK', '01')
					assert.isOk(req.claims, '02')
					assert.equal(req.claims.id, user.id, '03')
					assert.equal(req.claims.email, user.email, '04')
					done()
				}).catch(done)
			})
		})
	})
})









