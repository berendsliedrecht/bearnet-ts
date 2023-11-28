# Bearnet

> Name is partially inspired by [hairnet](https://github.com/ferd/hairnet)

Implementation of [fernet](https://github.com/fernet/spec/blob/20dead475f53f11d20592baf29ad697163afc0cd/Spec.md), but using XChaCha20Poly1305 (following [unofficial version 3](https://github.com/mikelodder7/fernet/blob/deccfda5ff8d3c407175a2eace570bd4b7adc5ad/specs/version3.md)).

### Cryptography

This library fully relies on [@noble/ciphers](https://paulmillr.com/noble/) which is an unaudited library, use with caution.

## Usage

### Bearnet generated key

```typescript
import { Bearnet } from 'bearnet'

const b = new Bearnet()

const token = b.encode('hello')
const msg = b.decode(token, { returnAsString: true })

assert(msg === 'hello')
```

### Or with your own key

```typescript
import { Bearnet } from 'bearnet'

const b = new Bearnet(new Uint8Array(32).fill(0))

const token = b.encode('hello')
const msg = b.decode(token, { returnAsString: true })

assert(msg === 'hello')
```

### Separated encoding and decoding

```typescript
import { Bearnet } from 'bearnet'

const b = new Bearnet(new Uint8Array(32).fill(0))

const token = b.encode('hello')
```

> Key and Token transfer happen OOB

```typescript
import { Bearnet } from 'bearnet'

const b = new Bearnet(new Uint8Array(32).fill(0))

const msg = b.decode(token, { returnAsString: true })

assert(msg === 'hello')
```
