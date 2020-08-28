# jwt-pwd &middot;  [![NPM](https://img.shields.io/npm/v/jwt-pwd.svg?style=flat)](https://www.npmjs.com/package/jwt-pwd) [![Tests](https://travis-ci.org/nicolasdao/jwt-pwd.svg?branch=master)](https://travis-ci.org/nicolasdao/jwt-pwd) [![License](https://img.shields.io/badge/License-BSD%203--Clause-blue.svg)](https://opensource.org/licenses/BSD-3-Clause) [![Neap](https://neap.co/img/made_by_neap.svg)](#this-is-what-we-re-up-to)
__*jwt-pwd*__ is a tiny encryption helper that manages JWT (JSON Web Token) tokens and encrypts and validates passwords using methods such as md5, sha1, sha256, sha512, ripemd160. It aims at facilitating the development of token based authentication and authorization APIs (e.g., REST, GraphQL). This package is a wrapper for the [jsonwebtoken package](https://www.npmjs.com/package/jsonwebtoken). 

# Table of Contents

> * [Install](#install) 
> * [How To Use It](#how-to-use-it) 
> 	- [Generate & Validate a JWT Token](#generate--validate-a-jwt-token) 
> 	- [Encrypt & Validate Passwords](#encrypt--validate-passwords) 
> 	- [Authorizing HTTP Request With a JWT Token (Express)](#authorizing-http-request-with-a-jwt-token-express) 
> 	- [Other Utils](#other-utils) 
> * [FAQ](#faq) 
> 	- [How to generate a secret?](#how-to-generate-a-secret) 
>	- [Why bearer tokens stored in cookies are not prefixed with bearer?](#why-bearer-tokens-stored-in-cookies-are-not-prefixed-with-bearer)
> * [About Neap](#this-is-what-we-re-up-to)
> * [License](#license)


# Install
```
npm i jwt-pwd
```

# How To Use It
## Generate & Validate a JWT Token

```js
const Encryption = require('jwt-pwd')
const { jwt } = new Encryption({ jwtSecret: 'your-jwt-secret' })

const claims = {
	id:1,
	email: 'you@coolcompany.com'
}

// 1. Create JWT
jwt.create(claims)
	.then(token => {
		console.log(`Your JWT: ${token}`)
		// 2. Validate JWT
		return jwt.validate(token) // validate returns a promise.
	})
	.then(validateClaims => {
		console.log(`User ID: ${validateClaims.id} - User email: ${validateClaims.email}`)
	})
	.catch(err => console.log(`Invalid token: ${err.message}`))

```

> WARNING: If the algorithm uses assymetric keys, the public key has to be passed as follow to validate the token:
>	```js
>	jwt.validate(token, { cert:publicKey })
>	```
> To learn more about using private/public keys, please refer to the example in the [Private/public keys for asymmetric algorithm](#privatepublic-keys-for-asymmetric-algorithm) section.

The default cryptographic algorithm is `HS256` (i.e., HMAC with SHA-256). The supported cryptographic algorithm are:
- `HS256`: HMAC signature with SHA-256 (symmetric key)
- `HS384`: HMAC signature with SHA-384 (symmetric key)
- `HS512`: HMAC signature with SHA-512 (symmetric key) 
- `RS256`: RSA signature with SHA-256 (asymmetric key)
- `RS384`: RSA signature with SHA-256 (asymmetric key) 
- `RS512`: RSA signature with SHA-256 (asymmetric key) 
- `PS256`: RSASSA-PSS signature with SHA-256 (asymmetric key) 
- `PS384`: RSASSA-PSS signature with SHA-256 (asymmetric key) 
- `PS512`: RSASSA-PSS signature with SHA-256 (asymmetric key) 
- `ES256`: ECDSA signature with SHA-256 (asymmetric key) 
- `ES384`: ECDSA signature with SHA-384 (asymmetric key) 
- `ES512`: ECDSA signature with SHA-512 (asymmetric key) 
- `none`: No signature

The key concept you must understand when it comes to choosing one of those algorithms is that they are mainly split in two categories:
- Asymmetric algorithm: The algorithm is using a private/public key to sign the token. The public key can be shared so the rest of the world can verify that the token has not been tampered. Because the private key is kept secret, there is very little risk of compromising the way the token is signed.
- Symmetric algorithm: The algorithm is using a single key to sign the token. This means that if a third party wish to verify that the token has not been tampered, the two parties needs to find a safe way to share the single key, which cna be risky. 

Choose a asymmetric algorithm if you must let clients verifying the JWT without your intervention. Once you've choosen which type of algorithm fits your requirements, choosing a specific algorithm depends on the types of keys you can generate. To learn more about generating keys, please refer to the [How to generate a secret?](#how-to-generate-a-secret) section.


To change the default algorithm, pass an option parameter as follow:

```js
jwt.create(claims, { algorithm:'HS512' })
```

## Encrypt & Validate Passwords

```js
const Encryption = require('jwt-pwd')
const { pwd } = new Encryption({ pwdSecret: 'your-pwd-secret' })

const password = 'your-super-safe-password'
const method = 'sha512' // other options: md5, sha1, sha256, sha512, ripemd160

// 1. Encrypt
const { salt, encryptedPassword } = pwd.encrypt({ password, method })
console.log(`Encrypted password: ${encryptedPassword} - Salt: ${salt}`)

// 2. Validate
console.log('Password validation result: ', pwd.validate({ password, encryptedPassword, salt, method })) 
console.log('Password validation result: ', pwd.validate({ password: '123', encryptedPassword, salt, method }))

```

> RECOMMENDATION: When using both `jwt` and `pwd`, do not use the same secret!

In theory, you could do one of the following:
```js
const { jwt, pwd } = new Encryption({ jwtSecret: 'your-jwt-secret' })
```

OR

```js
const { jwt, pwd } = new Encryption({ pwdSecret: 'your-pwd-secret' })
```

The above is deprecated as it would couple the encryption of the JWT and the password together. If access to one of them needs to be revoked, it won't be possible to revoke it without affecting the other. 

The recommended usage is to generate two different secret as follow:

```js
const { jwt, pwd } = new Encryption({ jwtSecret: 'your-jwt-secret', pwdSecret: 'your-pwd-secret' })
```

## Authorizing HTTP Request With a JWT Token (Express)

The following piece of code assume that a JWT token containing claims `{ firstName:'Nic' }` is passed to each request in the `Authorization` header. If the request is successfully authenticated, a new `claims` property is added to the `req` object. That property contains all the claims. If, on the contrary, the request fails the authentication handler, then a 403 code is immediately returned.

```js
const Encryption = require('jwt-pwd')
const { bearerHandler } = new Encryption({ jwtSecret: 'your-jwt-secret' })

app.get('/sayhi', bearerHandler(), (req,res) => res.status(200).send(`${req.claims.firstName} says hi.`))
```

#### bearerHandler(options)

* `options` `<Object>`
	- `key` 	`<String>` 	Default is 'Authorization'. This is the request's header that's supposed to contain the bearer token.
	- `cookie`  `<String>` 	Cookie's name storing the token. If specified, the token can be stored in that cookie.
	- `query`   `<String>` 	Query parameter's name storing the token. If specified, the token can be stored the request's query parameter (e.g., if query equals `code`, then the token can be passed using URL [https://neap.co/oauth2/token?code=32133213213123213](https://neap.co/oauth2/token?code=32133213213123213)).

## Other Utils
### Authorizing HTTP Request With an API Key (Express)

The following piece of code assume that an API key is passed in each request in the header `x-api-key` (this header key is configurable). If the request is successfully authenticated, the rest of the code is executed. If, on the contrary, the request fails the authentication handler, then a 403 code is immediately returned.

```js
const Encryption = require('jwt-pwd')
const { apiKeyHandler } = new Encryption({ jwtSecret: 'your-jwt-secret' })

app.get('/sayhello', apiKeyHandler({ key: 'x-api-key', value: 'your-api-key' }), (req,res) => res.status(200).send(`Hello`))
```

> NOTE: In this case, the `jwtSecret` is not involved in any encryption or validation. The `apiKeyHandler` is just a handy helper.

# FAQ
## How to generate a secret?

The method to generate a secret depends on your business requirements. If you need to let third parties to verify that your JWT has not been tampered, then you need to use private/public key with an asymmetric algorithm so you can safely share the public key. If on the other hand signing your JWT is a one-way street, you can use a symmetric algorithm and generate a single secret.

### Single key for symmetric algorithm

There are various way to do it. The quickest way is to use the native NodeJS core library `crypto` as follow:

```js
require('crypto').randomBytes(50).toString('base64')
````

Alternatively, there are plenty of websites that generate random key such as [https://keygen.io/](https://keygen.io/) or [https://randomkeygen.com/](#https://randomkeygen.com/).

### Private/public keys for asymmetric algorithm

Use OpenSSL to create a `.pem` file containing the private key. In this example, we'll use the ECDSA algorithm to generate a `key.pem` file:

```
openssl ecparam -genkey -name secp256k1 -noout -out key.pem
```

> The list of algorithms can for ECDSA can be listed with `openssl ecparam -list_curves`

Then generate a public key for this private key:

```
openssl ec -in key.pem -pubout > key.pub
```

To test your keys, use the following snippet:

```js
const Encryption = require('jwt-pwd')
const fs = require('fs')

const alg = 'ES256'
const privateKey = fs.readFileSync('./key.pem').toString()
const publicKey = fs.readFileSync('./key.pub').toString()
const { jwt } = new Encryption({ jwtSecret:privateKey })
const claims = {
	id:1,
	email: 'nic@neap.co'
}

jwt.create(claims, { algorithm:alg }).then(token => jwt.validate(token, { cert:publicKey, algorithms:[alg] })).then(console.log)
```

## Why bearer tokens stored in cookies are not prefixed with bearer?

Some libraries (e.g., `axios`) can use the access token stored in a cookie to automatically pass it into the `Authorization` header. When they do so, those libraries may add the `Bearer` prefix automatically. If the token was already prefixed with `Bearer`, the resulting token passed in the `Authorization` headers with be prefixed twice (e.g., `Bearer Bearer ...`) which would break the server side authentication.

# This Is What We re Up To
We are Neap, an Australian Technology consultancy powering the startup ecosystem in Sydney. We simply love building Tech and also meeting new people, so don't hesitate to connect with us at [https://neap.co](https://neap.co).

Our other open-sourced projects:
#### GraphQL
* [__*graphql-s2s*__](https://github.com/nicolasdao/graphql-s2s): Add GraphQL Schema support for type inheritance, generic typing, metadata decoration. Transpile the enriched GraphQL string schema into the standard string schema understood by graphql.js and the Apollo server client.
* [__*schemaglue*__](https://github.com/nicolasdao/schemaglue): Naturally breaks down your monolithic graphql schema into bits and pieces and then glue them back together.
* [__*graphql-authorize*__](https://github.com/nicolasdao/graphql-authorize.git): Authorization middleware for [graphql-serverless](https://github.com/nicolasdao/graphql-serverless). Add inline authorization straight into your GraphQl schema to restrict access to certain fields based on your user's rights.

#### React & React Native
* [__*react-native-game-engine*__](https://github.com/bberak/react-native-game-engine): A lightweight game engine for react native.
* [__*react-native-game-engine-handbook*__](https://github.com/bberak/react-native-game-engine-handbook): A React Native app showcasing some examples using react-native-game-engine.

#### General Purposes
* [__*core-async*__](https://github.com/nicolasdao/core-async): JS implementation of the Clojure core.async library aimed at implementing CSP (Concurrent Sequential Process) programming style. Designed to be used with the npm package 'co'.

#### Google Cloud Platform
* [__*google-cloud-bucket*__](https://github.com/nicolasdao/google-cloud-bucket): Nodejs package to manage Google Cloud Buckets and perform CRUD operations against them.
* [__*google-cloud-bigquery*__](https://github.com/nicolasdao/google-cloud-bigquery): Nodejs package to manage Google Cloud BigQuery datasets, and tables and perform CRUD operations against them.
* [__*google-cloud-tasks*__](https://github.com/nicolasdao/google-cloud-tasks): Nodejs package to push tasks to Google Cloud Tasks. Include pushing batches.

# License
Copyright (c) 2017-2019, Neap Pty Ltd.
All rights reserved.

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
* Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
* Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
* Neither the name of Neap Pty Ltd nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL NEAP PTY LTD BE LIABLE FOR ANY
DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

<p align="center"><a href="https://neap.co" target="_blank"><img src="https://neap.co/img/neap_color_horizontal.png" alt="Neap Pty Ltd logo" title="Neap" height="89" width="200"/></a></p>


