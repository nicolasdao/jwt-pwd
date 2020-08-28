/**
 * Copyright (c) 2017-2019, Neap Pty Ltd.
 * All rights reserved.
 * 
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
*/

/**
 * ENCRYPTION MANAGER
 * ------------------
 * 
 * Use the most common encryption algorithm (md5, sha1, sha256, sha512, ripemd160) 
 * to encrypt data using typically a salt key. This is a typical way of managing 
 * password as well as validating them. The workflows are as follow:
 *
 * 		1. Storing a new password
 * 		-------------------------
 * 			a. Generate a new salt.
 * 			b. Encrypt the password with that salt.
 * 			c. Store both that encrypted password and the salt in the DB.
 *    	
 *    	To make sure no users having access to the DB can decrypt those data, (which 
 *    	they theoretically could as they have both the encrypted password and the
 *    	salt), you can add to the salt randomly generated with 'randomHexSalt' another
 *    	secret key stored in your app. The salt stored in the DB is just half of it.
 *    	The other half is stored in your app. 
 *
 *		2. Validate the password
 *		------------------------
 *			a. Get the encrypted password and the salt from the DB
 *			b. Encrypt the provided password with the salt
 *			c. Compare that re-encrypted password with the stored encrypted one. 
 */

const hash = require('node_hash')
const crypto = require('crypto')
const jwt = require('jsonwebtoken')
const url = require('url')

const utf8ToHex = s => s ? Buffer.from(s).toString('hex') : ''
const hexToBuf = h => h ? Buffer.from(h, 'hex') : new Buffer(0)

/**
 * Creates new hex random salt.
 * 
 * @param  {Number} length Length of the random salt.
 * @return {String}        Salt
 */
const randomHexSalt = length => crypto.randomBytes(Math.ceil(length/2)).toString('hex') .slice(0,length)

/**
 * Creates new hex salt from a specific string.
 *
 * @param  {String} str 	Seed string.
 * @param  {Number} length 	Length of the random salt.
 * @return {String}        	Salt
 */
const stringToHexSalt = (str, length) => length ? utf8ToHex(str).slice(0,length) : utf8ToHex(str)

/**
 * Encrypts data using some of the most classic encryption algorithm.
 * 
 * @param  {String} data     	Data
 * @param  {String} method   	md5, sha1, sha256, sha512, ripemd160
 * @param  {String} hexSalt1 	Required Hexadecimal salt
 * @param  {String} hexSalt2 	Optional second Hexadecimal salt (e.g. keep that one in your app)
 * @return {String}          	Encrypted data
 */
const encryptData = (data, method, hexSalt1, hexSalt2) => {
	const saltBuf = hexToBuf(hexSalt1 + (hexSalt2 || ''))
	switch(method) {
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
		throw new Error(`Encryption method ${method} is not supported.`)
	}
}


const validateData = (data, encryptedData, method, hexSalt1, hexSalt2) => {
	try {
		const reEndryptedData = encryptData(data, method, hexSalt1, hexSalt2)
		return encryptedData == reEndryptedData
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

const Encryption = function({ jwtSecret, pwdSecret }) {
	if (!jwtSecret && !pwdSecret)
		throw new Error('Missing required arguments. At least one of the following arguments must be specified: \'jwtSecret\' or \'pwdSecret\'')

	if (!pwdSecret)
		pwdSecret = jwtSecret
	if (!jwtSecret)
		jwtSecret = pwdSecret

	const APP_PWD_SALT = stringToHexSalt(pwdSecret, 16)
	
	this.pwd = {
		/**
		 * Determines whether the password matches the encrypted password in the DB
		 * 
		 * @param  {String} password          	Password sent from the client
		 * @param  {String} encryptedPassword 	Password stored in the DB
		 * @param  {String} salt              	Salt stored in the DB
		 * @param  {String} method  			e.g., md5, sha1, sha256, sha512, ripemd160
		 * @return {Boolean}                  
		 */
		validate: ({ password, encryptedPassword, salt, method }) => validateData(password, encryptedPassword, method, salt, APP_PWD_SALT),
		/**
		 * Encrypts a password using a encryption method. 
		 * 
		 * @param  {String} password    				
		 * @param  {String} method 						e.g., md5, sha1, sha256, sha512, ripemd160
		 * @return {String} output.salt 				
		 * @return {String} output.encryptedPassword 	
		 */
		encrypt: ({ password, method }) => {
			const salt = randomHexSalt(16)
			return {
				salt,
				encryptedPassword: encryptData(password, method, salt, APP_PWD_SALT) 
			}
		}
	}

	const _jwt = {
		/**
		 * Creates a JWT token
		 * 
		 * @param  {Object}  claims 			Optional, e.g., { id:1, email: 'nic@neap.co' }
		 * @param  {String}  options.algorithm	Default: 'RS256'. Supported: HS256, HS384, HS512, RS256, RS384, RS512, PS256, PS384, PS512, ES256, ES384, ES512
		 * @return {Promise}        			Promise resolving to a string.
		 */
		create: (claims={}, options) => new Promise((onSuccess, onFailure) => jwt.sign(claims, jwtSecret, options, (err, token) => {
			if (err)
				onFailure(err)
			else
				onSuccess(token)
		})),

		/**
		 * Verifies whether or not the token is valid based on whether it can be decrypted or not. 
		 * 
		 * @param  {String} 	token 
		 * @param  {[String]}   options.algorithms 
		 * @return {Promise}    Promise resolving to a Claims object
		 */
		validate: (token='', options) => {
			const { cert:c, algorithms } = options || {}
			const cert = c || jwtSecret
			const opts = algorithms ? { algorithms } : {}
			return new Promise((onSuccess, onFailure) => jwt.verify(token, cert, opts, (err, claims) => {
				if (err)
					onFailure(err)
				else
					onSuccess(claims)
			}))
		},

		/**
		 * Decodes a JWT. 
		 * 
		 * @param  {String}  token
		 * @param  {Boolean} options.complete	Default false. When set to true, the decoding includes the header and the signature. 		
		 * @return {Object}
		 */
		decode: (token, options) => jwt.decode(token, options)
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

module.exports = Encryption






