/**
 * Copyright (c) 2017-2019, Neap Pty Ltd.
 * All rights reserved.
 * 
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
*/

/**
 * CRYPTO MANAGER
 * ------------------
 * 
 * Use the most common hashing algorithms ('md5', 'sha1', 'sha256', 'sha512', 'ripemd160') 
 * to hash data with a salt key. This is a typical way of managing 
 * password as well as validating them. The workflows are as follow:
 *
 * 		1. Storing a new password
 * 		-------------------------
 * 			a. Generate a new salt.
 * 			b. Hash the password with that salt.
 * 			c. Store both that hashed password and the salt in the DB.
 *    	
 *
 *		2. Validate the password
 *		------------------------
 *			a. Get the hashed password and the salt from the DB
 *			b. Hash the provided password with the salt
 *			c. Compare that re-hashed password with the stored hashed one. 
 */

const hash = require('node_hash')
const crypto = require('crypto')
const jwt = require('jsonwebtoken')
const url = require('url')

const hexToBuf = h => h ? Buffer.from(h, 'hex') : new Buffer(0)

/**
 * Creates new hex random salt.
 * 
 * @param  {Number} length Length of the random salt.
 * @return {String}        Salt
 */
const randomHexSalt = length => crypto.randomBytes(Math.ceil(length/2)).toString('hex') .slice(0,length)

/**
 * Hashes salted data using some of the common hashing algorithm.
 * 
 * @param  {String} data     	Data
 * @param  {String} alg   		'md5', 'sha1', 'sha256', 'sha512', 'ripemd160'
 * @param  {String} hexSalt 	Required Hexadecimal salt
 * @return {String}          	Hashed data
 */
const hashSaltedData = (data, alg, hexSalt) => {
	const saltBuf = hexToBuf(hexSalt)
	switch(alg) {
	case 'md5':
		return hash.md5(data, saltBuf)
	case 'sha1':
		return hash.sha1(data, saltBuf)
	case 'sha256':
		return hash.sha256(data, saltBuf)
	case 'sha512':
		return hash.sha512(data, saltBuf)
	case 'ripemd160':
		return hash.ripemd160(data, saltBuf)
	default:
		throw new Error(`Hash algorithm ${alg} is not supported.`)
	}
}


const validateData = (data, hashedData, alg, hexSalt) => {
	try {
		const reHashedData = hashSaltedData(data, alg, hexSalt)
		return hashedData == reHashedData
	}
	/*eslint-disable */
	catch(err) {
		/*eslint-enable */
		return false
	}
}

const getBearerFromCookie = (cname,req) => {
	const cookie = ((req || {}).headers || {}).cookie
	
	if (!cname || !cookie)
		return ''

	const name = cname + '='
	const decodedCookie = decodeURIComponent(cookie)
	const ca = decodedCookie.split(';')
	for(let i = 0; i <ca.length; i++) {
		let c = ca[i]
		while (c.charAt(0) == ' ')
			c = c.substring(1)
		if (c.indexOf(name) == 0) {
			const v = c.substring(name.length, c.length) 
			return v ? `Bearer ${v}` : ''
		}
	}
	return ''
}

const getBearerFromQuery = (qname,req) => {
	try {
		const u = (req||{}).url 
		if (!qname || !u)
			return ''

		const { search:querystring } = new url.URL(u)
		if (!querystring)
			return ''

		const obj = querystring.replace(/^\?/,'').split('&').reduce((acc,keyValue) => {
			if (keyValue) {
				const [key,...values] = keyValue.split('=')
				const value = decodeURIComponent(values.join('='))
				acc[key] = value
			}
			return acc
		}, {})
		const v = obj[qname] || ''
		return v ? `Bearer ${v}` : ''
	} catch(e) {
		return (() => '')(e)
	}
}

const ENCODING_OUTPUT_FORMAT = 'hex'
const TRIPLE_DES = 'des-ede3'
const AES = 'aes-256-cbc'
/**
 * Encrypts string using your own explicit algorithm or default back to AES ('aes-256-cbc') or Triple DES ('des-ede3') based on the
 * data available. 
 * 
 * @param  {String} text		
 * @param  {String} key					Encryption key.		
 * @param  {String} options.cipher		
 * @param  {String} options.iv			Initialization vector (required if 'optiions.cipher' is 'aes-256-cbc'
 * @param  {String} options.format		Default 'hex'. Valid values: 'base64', 'hex', 'buffer'
 * 
 * @return {String} output.encrypted
 * @return {String} output.iv
 */
const encrypt = (text, key, options) => {
	let { iv, cipher, format=ENCODING_OUTPUT_FORMAT } = options || {}
	const errorMsg = `Failed to encrypt data${cipher ? ` using the '${cipher}' cipher` : ''}`
	if (!key)
		throw new Error(`${errorMsg}. Missing required 'key'.`)

	if (format != 'hex' && format != 'base64' && format != 'buffer')
		throw new Error(`${errorMsg}. format '${format}' is not supported. Supported formats are: 'base64', 'hex', 'buffer'`)

	let encryptionKey = key
	if (!cipher) {
		if (!iv) {
			if (key.length < 24)
				throw new Error(`${errorMsg}. Invalid key length. To default to Triple DES cipher, the key must be 24 characters long.`)

			encryptionKey = key.slice(0,24)
			cipher = TRIPLE_DES
		} else {
			if (key.length < 32)
				throw new Error(`${errorMsg}. Invalid key length. To default to AES cipher, the key must be 32 characters long.`)
			
			encryptionKey = key.slice(0,32)
			cipher = AES
		}
	}

	if (cipher === AES) {
		if (!iv)
			throw new Error(`${errorMsg}. The ${AES} cipher requires an initialization vector ('iv' option).`)
		if (iv.length != 16)
			throw new Error(`${errorMsg}. The ${AES} requires an initialization vector ('iv' option) that is 16 characters long (current is ${iv.length})`)
	}

	try {
		const cipherObj = crypto.createCipheriv(cipher, encryptionKey, iv||null)
		const encryptedBuffer = Buffer.concat([cipherObj.update(text||''), cipherObj.final()])
		return {
			cipher,
			key: encryptionKey,
			encrypted: format == 'buffer' ? encryptedBuffer : encryptedBuffer.toString(format),
			iv:iv||null,
			format
		}
	} catch (err) {
		throw new Error(`${errorMsg}. ${err.message}`)
	}
}

/**
 * Decrypts string using the 'aes-256-cbc' cipher. 
 *
 * @param  {String} text	
 * @param  {String} key					Decryption key
 * @param  {String} iv					Initialization vector
 * @param  {String} options.cipher		Default 'aes-256-cbc'
 * @param  {String} options.iv			Initialization vector (required if 'optiions.cipher' is 'aes-256-cbc'
 * @param  {String} options.format		Default 'hex'. Valid values: 'base64', 'hex', 'buffer'
 * 
 * @return {String} decrypted
 */
const decrypt = (text, key, options) => {
	let { cipher, iv, format=ENCODING_OUTPUT_FORMAT } = options || {}
	cipher = cipher || AES
	const errorMsg = `Failed to decript data using the '${cipher}' cipher`

	if (text instanceof Buffer)
		format = null

	if (!key)
		throw new Error(`${errorMsg}. Missing required 'key'.`)

	if (cipher === AES) {
		if (!iv)
			throw new Error(`${errorMsg}. The ${AES} cipher requires an initialization vector ('iv' option).`)
		if (iv.length != 16)
			throw new Error(`${errorMsg}. The ${AES} requires an initialization vector ('iv' option) that is 16 characters long (current is ${iv.length})`)
	}

	try {
		const decipher = crypto.createDecipheriv(cipher, key, iv||null)
		const decrypted = Buffer.concat([decipher.update(text||'', format), decipher.final()]).toString()
		return decrypted
	} catch (err) {
		throw new Error(`${errorMsg}. ${err.message}`)
	}
}

/**
 * Merges the input secrets into the a consistant set of keys. 
 * 
 * @param  {Object} secret        Object or string. If it exists and all the others don't, then its value(s) are used to set all the others.
 * @param  {Object} jwtSecret     Object or string used to sign JWT
 * @param  {Object} encryptSecret [description]
 * @return {Object}                       [description]
 */
const _getSecrets = ({ secret, jwtSecret, encryptSecret }) => {
	let privateJwtKey, publicJwtKey, privateEncryptKey, publicEncryptKey, iv
	
	const secretType = secret ? typeof(secret) : null
	const jwtSecretType = jwtSecret ? typeof(jwtSecret) : null
	const encryptSecretType = encryptSecret ? typeof(encryptSecret) : null

	if (!jwtSecret && secret) {
		if (secretType == 'string') {
			privateJwtKey = secret
			publicJwtKey = secret
		} else if (secretType == 'object') {
			privateJwtKey = secret.privateKey
			publicJwtKey = secret.publicKey
		}
	} else if (jwtSecret) {
		if (jwtSecretType == 'string') {
			privateJwtKey = jwtSecret
			publicJwtKey = jwtSecret
		} else if (jwtSecretType == 'object') {
			privateJwtKey = jwtSecret.privateKey
			publicJwtKey = jwtSecret.publicKey
		}
	}

	if (!encryptSecret && secret) {
		if (secretType == 'string') {
			privateEncryptKey = secret
			publicEncryptKey = secret
		} else if (secretType == 'object') {
			privateEncryptKey = secret.privateKey
			publicEncryptKey = secret.publicKey
			iv = secret.iv
		}
	} else if (encryptSecret) {
		if (encryptSecretType == 'string') {
			privateEncryptKey = encryptSecret
			publicEncryptKey = encryptSecret
		} else if (encryptSecretType == 'object') {
			privateEncryptKey = encryptSecret.privateKey
			publicEncryptKey = encryptSecret.publicKey
			iv = encryptSecret.iv
		}
	}

	return { privateJwtKey, publicJwtKey, privateEncryptKey, publicEncryptKey, iv }
}

const generateAESkey = (format) => crypto.randomBytes(32).toString(format || 'hex').slice(0, 32)
const generateAESiv = (format) => crypto.randomBytes(16).toString(format || 'hex').slice(0, 16)
const generateDESkey = (format) => crypto.randomBytes(24).toString(format || 'hex').slice(0, 24)

/**
 * Creates a Crypto object. 
 * 
 * @param {String||Object} 	config.secret						key or object
 * @param {String} 			config.secret.privateKey		
 * @param {String} 			config.secret.publicKey		
 * @param {String} 			config.secret.iv					Initialization vector. Only used for encryption when the algorithm is AES
 * @param {String||Object} 	config.jwtSecret					key or object
 * @param {String} 			config.jwtSecret.privateKey		
 * @param {String} 			config.jwtSecret.publicKey		
 * @param {String||Object} 	config.encryptSecret				key or object
 * @param {String} 			config.encryptSecret.privateKey		
 * @param {String} 			config.encryptSecret.publicKey		
 * @param {String} 			config.encryptSecret.iv				Initialization vector. Only used for encryption when the algorithm is AES
 *
 * @return {Crypto}			crypto
 */
const Crypto = function(config) {
	const { secret, jwtSecret, encryptSecret } = config || {}
	let { privateJwtKey, publicJwtKey, privateEncryptKey, publicEncryptKey, iv } = _getSecrets({ secret, jwtSecret, encryptSecret })
	
	this.pwd = {
		/**
		 * Determines whether the password matches the hashed password in the DB
		 * 
		 * @param  {String} password          		Password sent from the client
		 * @param  {String} hashedSaltedPassword 	Password stored in the DB
		 * @param  {String} salt              		Salt stored in the DB
		 * @param  {String} alg  					Default is 'sha256'. Supported values: 'md5', 'sha1', 'sha256', 'sha512', 'ripemd160'
		 * @return {Boolean}                  
		 */
		validate: ({ password, hashedSaltedPassword, salt, alg='sha256' }) => validateData(password, hashedSaltedPassword, alg, salt),
		/**
		 * Hashes a salted password using the hash alg. 
		 * 
		 * @param  {String} password    				
		 * @param  {String} alg 						Default is 'sha256'. Supported values: 'md5', 'sha1', 'sha256', 'sha512', 'ripemd160'
		 * @return {String} output.salt 				
		 * @return {String} output.hashedSaltedPassword 	
		 */
		hashAndSalt: ({ password, alg='sha256' }) => {
			const salt = randomHexSalt(16)
			return {
				salt,
				hashedSaltedPassword: hashSaltedData(password, alg, salt) 
			}
		}
	}

	const _jwt = {
		setKey: (key, options) => {
			const { format, length } = options || {}
			privateJwtKey = key || crypto.randomBytes(length || 50).toString(format || 'base64')
			return privateJwtKey
		},
		getKey: () => privateJwtKey,
		/**
		 * Creates a JWT token
		 * 
		 * @param  {Object}  claims 			Optional, e.g., { id:1, email: 'nic@neap.co' }
		 * @param  {String}  options.algorithm	Default: 'RS256'. Supported: HS256, HS384, HS512, RS256, RS384, RS512, PS256, PS384, PS512, ES256, ES384, ES512
		 * @return {Promise}        			Promise resolving to a string.
		 */
		create: (claims={}, options) => new Promise((onSuccess, onFailure) => {
			if (!privateJwtKey)
				onFailure(new Error('Failed to create JWT. Missing required private key. Please use one of the following constructors to instantiate your Crypto object: new Crypto({ secret:\'priv-key\' }), new Crypto({ secret: { privateKey:\'priv-key\' } }),new Crypto({ jwtSecret:\'priv-key\' }), new Crypto({ jwtSecret: { privateKey:\'priv-key\' } }).'))
			jwt.sign(claims, privateJwtKey, options, (err, token) => {
				if (err)
					onFailure(err)
				else
					onSuccess(token)
			})
		}),

		/**
		 * Verifies whether or not the token is valid based on whether it can be decrypted or not. 
		 * 
		 * @param  {String} 	token 
		 * @param  {String}     options.key			Public key to decrypt the JWT.
		 * @param  {[String]}   options.algorithms 
		 * @return {Promise}    Promise resolving to a Claims object
		 */
		validate: (token='', options) => new Promise((onSuccess, onFailure) => {
			const { key, algorithms } = options || {}
			const cert = key || publicJwtKey || privateJwtKey
			const opts = algorithms ? { algorithms } : {}

			if (!cert)
				onFailure(new Error('Failed to verify JWT. Missing required \'key\'/'))

			jwt.verify(token, cert, opts, (err, claims) => {
				if (err)
					onFailure(err)
				else
					onSuccess(claims)
			})
		}),

		/**
		 * Decodes a JWT. 
		 * 
		 * @param  {String}  token
		 * @param  {Boolean} options.complete	Default false. When set to true, the decoding includes the header and the signature. 		
		 * @return {Object}
		 */
		decode: (token, options) => jwt.decode(token, options)
	}

	this.encryption = {
		aes: {
			setKey: key => {
				privateEncryptKey = key || generateAESkey()
				return privateEncryptKey
			},
			getKey: () => privateEncryptKey,
			setIv: () => {
				iv = generateAESiv()
				return iv
			},
			generateKey: generateAESkey,
			generateIv: generateAESiv,
			/**
			 * Encrypts string using the 'aes-256-cbc' cipher. 
			 * 
			 * @param  {String} text				
			 * @param  {String} options.format		Default 'hex'. Valid values: 'base64', 'hex', 'buffer'
			 * 
			 * @return {String} output.encrypted
			 * @return {String} output.iv
			 */
			encrypt: (text, options={}) => encrypt(text, privateEncryptKey, { ...options, iv, cipher:AES }),
			/**
			 * Decrypts string using the 'aes-256-cbc' cipher. 
			 *
			 * @param  {String} text	
			 * @param  {String} options.key			
			 * @param  {String} options.format		Default 'hex'. Valid values: 'base64', 'hex', 'buffer'
			 * 
			 * @return {String} decrypted
			 */
			decrypt: (text, options={}) => decrypt(text, options.key || publicEncryptKey || privateEncryptKey, { ...options, iv, cipher:AES })
		},
		des: {
			setKey: key => {
				privateEncryptKey = key || generateDESkey()
				return privateEncryptKey
			},
			generateKey: generateDESkey,
			/**
			 * Encrypts string using the 'aes-256-cbc' cipher. 
			 * 
			 * @param  {String} text				
			 * @param  {String} options.format		Default 'hex'. Valid values: 'base64', 'hex', 'buffer'
			 * 
			 * @return {String} output.encrypted
			 * @return {String} output.iv
			 */
			encrypt: (text, options={}) => encrypt(text, privateEncryptKey, { ...options, iv, cipher:TRIPLE_DES }),
			/**
			 * Decrypts string using the 'aes-256-cbc' cipher. 
			 *
			 * @param  {String} text	
			 * @param  {String} options.key			
			 * @param  {String} options.format		Default 'hex'. Valid values: 'base64', 'hex', 'buffer'
			 * 
			 * @return {String} decrypted
			 */
			decrypt: (text, options={}) => decrypt(text, options.key || publicEncryptKey || privateEncryptKey, { ...options, iv, cipher:TRIPLE_DES })
		},
		/**
		 * Encrypts string using the most appropriate cipher. 
		 * 
		 * @param  {String} text				
		 * @param  {String} options.cipher		
		 * @param  {String} options.format		Default 'hex'. Valid values: 'base64', 'hex', 'buffer'
		 * 
		 * @return {String} output.encrypted
		 * @return {String} output.iv
		 */
		encrypt: (text, options={}) => encrypt(text, privateEncryptKey, { ...options, iv }),
		/**
		 * Decrypts string using the most appropriate cipher. 
		 *
		 * @param  {String} text	
		 * @param  {String} options.cipher		Default 'aes-256-cbc'
		 * @param  {String} options.key			
		 * @param  {String} options.format		Default 'hex'. Valid values: 'base64', 'hex', 'buffer'
		 * 
		 * @return {String} decrypted
		 */
		decrypt: (text, options={}) => decrypt(text, options.key || publicEncryptKey || privateEncryptKey, { ...options, iv })
	}

	this.jwt = _jwt

	this.apiKeyHandler = ({ key, value }) => {
		if (!key)
			throw new Error('Missing required argument \'key\'')
		if (!value)
			throw new Error('Missing required argument \'value\'')

		return (req,res,next) => {
			const keyValue = (req.headers || {})[key]
			if (keyValue != value)
				res.status(403).send(`Unauthorized access. ${keyValue ? `Invalid API key '${key}'.` : `Missing API key. Header '${key}' not found.`}`)
			next()
		}
	}

	this.bearerHandler = (options) => {
		const { key='Authorization', cookie, query, redirectUrl } = options || {}
		return (req,res,next) => {
			const headers = req.headers || {}
			const keyValue = key == 'Authorization' ? (headers[key] || headers['authorization']) : headers[key]
			const cookieValue = cookie ? getBearerFromCookie(cookie, req) : ''
			const queryValue = query ? getBearerFromQuery(query, req) : ''
			const bearerToken = cookieValue || queryValue ||keyValue
			if (!bearerToken) {
				redirectUrl 
					? res.redirect(redirectUrl)
					: res.status(403).send(`Unauthorized access. Missing bearer token. Header '${key}' not found.`)
				next()
			} else if (!/^[bB]earer\s/.test(bearerToken)) {
				redirectUrl 
					? res.redirect(redirectUrl)
					: res.status(403).send('Unauthorized access. Malformed bearer token. Missing bearer schema.')
				next()
			} else {
				const token = bearerToken.trim().replace(/^[bB]earer\s/, '')
				_jwt.validate(token)
					.catch(err => redirectUrl 
						? res.redirect(redirectUrl)
						: res.status(403).send(`Unauthorized access. Invalid bearer token. ${err.message}`))
					.then(claims => {
						if (claims)
							req.claims = claims 
						next()
					})
			}
		}
	}

	return this
}

module.exports = Crypto






