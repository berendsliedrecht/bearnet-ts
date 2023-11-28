import { xchacha20poly1305 } from '@noble/ciphers/chacha'
import { bytesToUtf8, utf8ToBytes } from '@noble/ciphers/utils'
import { randomBytes } from '@noble/ciphers/webcrypto/utils'

export class BearnetError extends Error {}

const timestampOffset = 1
const timestampSize = 8

const nonceOffset = 9
const nonceSize = 24

const versionTimestampSize = 9
const versionTimestampNonceSize = 33
const keySize = 32
const minimalTokenLength = 49

export class Bearnet {
    private version: number = 0x20
    private key = randomBytes(keySize)

    public constructor(key?: Uint8Array) {
        if (key) this.key = key
    }

    public static createKey() {}

    public encode(
        message: Uint8Array | string,
        iv: Uint8Array = randomBytes(nonceSize),
        timestamp: Date = new Date()
    ) {
        if (iv.length !== nonceSize) {
            throw new BearnetError(
                `iv has an incorrect length. Expected '${nonceSize}', received '${iv.length}'`
            )
        }

        const secondsSinceUnixEpoch = String(
            Math.round(timestamp.getTime() / 1000)
        )

        const paddedSeconds = secondsSinceUnixEpoch.padStart(timestampSize, '0')

        const aad = new Uint8Array(versionTimestampNonceSize)
        aad[0] = this.version
        aad.set(Uint8Array.from(paddedSeconds, Number), timestampOffset)
        aad.set(iv, nonceOffset)

        const chacha = xchacha20poly1305(this.key, iv, aad)
        const data =
            typeof message === 'string' ? utf8ToBytes(message) : message

        const ciphertext = chacha.encrypt(data)

        const token = new Uint8Array(
            versionTimestampNonceSize + ciphertext.length
        )

        token.set(aad)
        token.set(ciphertext, versionTimestampNonceSize)

        return token
    }

    public decode(
        token: Uint8Array,
        {
            ttl = -1,
            returnAsString = false
        }: {
            ttl?: number
            returnAsString?: boolean
        } = {
            ttl: -1,
            returnAsString: false
        }
    ): Uint8Array | string {
        if (token[0] !== this.version) {
            throw new BearnetError(
                `Incorrect version. Expected: '${this.version}', received: '${token[0]}'`
            )
        }

        if (token.length < versionTimestampNonceSize) {
            throw new BearnetError(
                `Invalid token length. Expected at least '${minimalTokenLength}', received '${token.length}'`
            )
        }

        const timestamp = parseInt(
            token
                .slice(timestampOffset, timestampOffset + timestampSize)
                .join(''),
            10
        )

        if (ttl >= 0 && timestamp + ttl < Math.round(Date.now() / 1000)) {
            throw new BearnetError(`Expired timestamp`)
        }

        const ciphertext = token.slice(versionTimestampNonceSize)
        const nonce = token.slice(
            versionTimestampSize,
            versionTimestampSize + nonceSize
        )
        const aad = token.slice(0, versionTimestampNonceSize)

        const chacha = xchacha20poly1305(this.key, nonce, aad)

        const plaintext = chacha.decrypt(ciphertext)

        return returnAsString ? bytesToUtf8(plaintext) : plaintext
    }
}
