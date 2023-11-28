import { describe, it } from 'node:test'

import { Bearnet } from '../src'
import assert, { strictEqual } from 'node:assert'

describe('bearnet', () => {
    it('should create bearnet instance', () => {
        const b = new Bearnet()

        assert(b instanceof Bearnet)
    })

    describe('encode', () => {
        it('string', () => {
            const b = new Bearnet()

            const arr = b.encode('Hello World!')

            assert(arr instanceof Uint8Array)
        })

        it('uint8array', () => {
            const b = new Bearnet()

            const arr = b.encode(new Uint8Array(32).fill(42))

            assert(arr instanceof Uint8Array)
        })

        it('test vector #01', () => {
            const b = new Bearnet(new Uint8Array(32).fill(0))
            const ciphertext = b.encode(
                'Hello!',
                new Uint8Array(24).fill(0),
                new Date(0)
            )

            strictEqual(
                Buffer.from(ciphertext).toString('hex'),
                '20000000000000000000000000000000000000000000000000000000000000000030fbfae58a01ef10b62b525b2caa4d7ff3b16f85df7a'
            )
        })
    })

    describe('decode', () => {
        it('should decode a message', () => {
            const b = new Bearnet(new Uint8Array(32).fill(0))
            const ciphertext = Uint8Array.from(
                Buffer.from(
                    '20000000000000000000000000000000000000000000000000000000000000000030fbfae58a01ef10b62b525b2caa4d7ff3b16f85df7a',
                    'hex'
                )
            )

            const msg = b.decode(ciphertext, { returnAsString: true })

            strictEqual(msg, 'Hello!')
        })
    })

    describe('roundtrip', () => {
        it('simple', () => {
            const b = new Bearnet()
            const msg = 'Bonjour'

            const ciphertext = b.encode(msg)
            const plaintext = b.decode(ciphertext, { returnAsString: true })

            strictEqual(plaintext, msg)
        })

        it('more complex', () => {
            const b = new Bearnet()
            const msg =
                'Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi'

            const ciphertext = b.encode(msg)
            const plaintext = b.decode(ciphertext, { returnAsString: true })

            strictEqual(plaintext, msg)
        })
    })
})
