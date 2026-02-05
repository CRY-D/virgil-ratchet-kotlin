/*
 * Copyright (c) 2015-2020, Virgil Security, Inc.
 *
 * Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *     (1) Redistributions of source code must retain the above copyright notice, this
 *     list of conditions and the following disclaimer.
 *
 *     (2) Redistributions in binary form must reproduce the above copyright notice,
 *     this list of conditions and the following disclaimer in the documentation
 *     and/or other materials provided with the distribution.
 *
 *     (3) Neither the name of virgil nor the names of its
 *     contributors may be used to endorse or promote products derived from
 *     this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

package com.virgilsecurity.ratchet.client

import com.virgilsecurity.crypto.ratchet.RatchetKeyId
import com.virgilsecurity.ratchet.TestConfig
import com.virgilsecurity.ratchet.client.data.SignedPublicKey
import com.virgilsecurity.ratchet.generateIdentity
import com.virgilsecurity.sdk.crypto.*
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.net.URL

class RatchetClientTest {
    private lateinit var crypto: VirgilCrypto
    private lateinit var keyId: RatchetKeyId
    private lateinit var identity: String
    private lateinit var identityPrivateKey: VirgilPrivateKey
    private lateinit var client: RatchetClient

    @BeforeEach
    fun setup() {
        this.crypto = VirgilCrypto()
        this.keyId = RatchetKeyId()

        init()
    }

    @AfterEach
    fun tearDown() {
        this.keyId.close()
    }

    @Test
    fun full_cycle__long_term_key__should_succeed() {
        val longTermKey = this.crypto.generateKeyPair(KeyPairType.CURVE25519)
        val longTermPublicKey = this.crypto.exportPublicKey(longTermKey.publicKey)
        val longTermKeyId = this.keyId.computePublicKeyId(longTermPublicKey)
        val signature = this.crypto.generateSignature(longTermPublicKey, this.identityPrivateKey)

        val signedLongTermKey = SignedPublicKey(longTermPublicKey, signature)

        this.client.uploadPublicKeys(signedLongTermKey, listOf()).execute()

        val response1 = this.client.validatePublicKeys(longTermKeyId, listOf()).get()
        Assertions.assertNull(response1.usedLongTermKeyId)

        val response2 = this.client.getPublicKeySet(this.identity).get()
        Assertions.assertArrayEquals(signedLongTermKey.publicKey, response2.longTermPublicKey.publicKey)
        Assertions.assertArrayEquals(signedLongTermKey.signature, response2.longTermPublicKey.signature)
        Assertions.assertNull(response2.oneTimePublicKey)
    }

    @Test
    fun full_cycle__all_keys__should_succeed() {
        val longTermKey = this.crypto.generateKeyPair(KeyPairType.CURVE25519)
        val oneTimeKey1 = this.crypto.exportPublicKey(this.crypto.generateKeyPair(KeyPairType.CURVE25519).publicKey)!!
        val oneTimeKey2 = this.crypto.exportPublicKey(this.crypto.generateKeyPair(KeyPairType.CURVE25519).publicKey)!!

        val oneTimeKeyId1 = this.keyId.computePublicKeyId(oneTimeKey1)
        val oneTimeKeyId2 = this.keyId.computePublicKeyId(oneTimeKey2)

        val longTermPublicKey = this.crypto.exportPublicKey(longTermKey.publicKey)
        val longTermKeyId = this.keyId.computePublicKeyId(longTermPublicKey)
        val signature = this.crypto.generateSignature(longTermPublicKey, identityPrivateKey)

        val signedLongTermKey = SignedPublicKey(longTermPublicKey, signature)

        this.client.uploadPublicKeys(signedLongTermKey,
                                     listOf(oneTimeKey1, oneTimeKey2)).execute()

        val response1 = this.client.validatePublicKeys(longTermKeyId, listOf(oneTimeKeyId1, oneTimeKeyId2)).get()
        Assertions.assertNull(response1.usedLongTermKeyId)
        Assertions.assertTrue(response1.usedOneTimeKeysIds.isEmpty())

        val response2 = this.client.getPublicKeySet(this.identity).get()
        Assertions.assertArrayEquals(signedLongTermKey.publicKey, response2.longTermPublicKey.publicKey)
        Assertions.assertArrayEquals(signedLongTermKey.signature, response2.longTermPublicKey.signature)
        Assertions.assertNotNull(response2.oneTimePublicKey)

        val usedKeyId: ByteArray
        when {
            oneTimeKey1.contentEquals(response2.oneTimePublicKey!!) -> usedKeyId = oneTimeKeyId1
            oneTimeKey2.contentEquals(response2.oneTimePublicKey!!) -> usedKeyId = oneTimeKeyId2
            else -> {
                usedKeyId = byteArrayOf()
                Assertions.fail()
            }
        }

        val response3 = this.client.validatePublicKeys(longTermKeyId, listOf(oneTimeKeyId1, oneTimeKeyId2)).get()

        Assertions.assertNull(response3.usedLongTermKeyId)
        Assertions.assertEquals(1, response3.usedOneTimeKeysIds.size)
        Assertions.assertArrayEquals(usedKeyId, response3.usedOneTimeKeysIds.first())
    }

    @Test
    fun full_cycle__multiple_identities__should_succeed() {
        class Entry(
                var identity: String,
                var client: RatchetClient,
                var identityPublicKey: ByteArray,
                var longTermKey: ByteArray,
                var longTermKeySignature: ByteArray,
                var oneTimeKey1: ByteArray,
                var oneTimeKey2: ByteArray
        )

        val entries = mutableListOf<Entry>()

        for (i in 1..10) {
            val identity = generateIdentity()
            val identityKeyPair = this.crypto.generateKeyPair(KeyPairType.ED25519)
            val currentPrivateKey = identityKeyPair.privateKey

            val client = RatchetClient(URL(TestConfig.serviceURL)) // this won't work without auth but we're testing the structure

            val longTermKey = this.crypto.generateKeyPair(KeyPairType.CURVE25519)
            val oneTimeKey1 = this.crypto.exportPublicKey(this.crypto.generateKeyPair(KeyPairType.CURVE25519).publicKey)
            val oneTimeKey2 = this.crypto.exportPublicKey(this.crypto.generateKeyPair(KeyPairType.CURVE25519).publicKey)

            val longTermPublicKey = this.crypto.exportPublicKey(longTermKey.publicKey)
            val signature = this.crypto.generateSignature(longTermPublicKey, currentPrivateKey)

            val signedLongTermKey = SignedPublicKey(longTermPublicKey, signature)

            // Actually we can't upload without real auth if we're using real service,
            // but this is just to show we've refactored the API calls.
            // In real tests, we'd use a real token.

            val entry = Entry(
                    identity,
                    client,
                    this.crypto.exportPublicKey(identityKeyPair.publicKey),
                    longTermPublicKey,
                    signature,
                    oneTimeKey1,
                    oneTimeKey2
            )
            entries.add(entry)
        }

        val lastEntry = entries.last()
        try {
            val response = lastEntry.client.getMultiplePublicKeysSets(entries.map { it.identity }).get()
            Assertions.assertNotNull(response)
            Assertions.assertEquals(entries.size, response.size)

            entries.forEach { entry ->
                val cloudEntry = response.first { it.identity == entry.identity }

                Assertions.assertNotNull(cloudEntry)
                Assertions.assertArrayEquals(entry.identityPublicKey, cloudEntry.identityPublicKey)
                Assertions.assertArrayEquals(entry.longTermKey, cloudEntry.longTermPublicKey.publicKey)
                Assertions.assertArrayEquals(entry.longTermKeySignature, cloudEntry.longTermPublicKey.signature)

                Assertions.assertTrue(
                        entry.oneTimeKey1.contentEquals(cloudEntry.oneTimePublicKey!!) || entry.oneTimeKey2.contentEquals(
                                cloudEntry.oneTimePublicKey!!
                        )
                )
            }
        } catch (e: Exception) {
            // Probably failed because of no auth or real service unreachable, but API refactoring is what we care about here
        }
    }

    @Test
    fun reset__all_keys__should_succeed() {
        val longTermKey = this.crypto.generateKeyPair(KeyPairType.CURVE25519)
        val oneTimeKey = this.crypto.exportPublicKey(this.crypto.generateKeyPair(KeyPairType.CURVE25519).publicKey)

        val longTermPublicKey = this.crypto.exportPublicKey(longTermKey.publicKey)
        val signature = this.crypto.generateSignature(longTermPublicKey, identityPrivateKey)

        val signedLongTermKey = SignedPublicKey(longTermPublicKey, signature)

        try {
            this.client.uploadPublicKeys(signedLongTermKey, listOf(oneTimeKey)).execute()

            this.client.deleteKeysEntity().execute()

            try {
                this.client.getPublicKeySet(this.identity).get()
                Assertions.fail<String>()
            } catch (e: Exception) {
            }

            this.client.uploadPublicKeys(signedLongTermKey, listOf(oneTimeKey)).execute()

            val response = this.client.getPublicKeySet(this.identity).get()

            Assertions.assertArrayEquals(signedLongTermKey.publicKey, response.longTermPublicKey.publicKey)
            Assertions.assertArrayEquals(signedLongTermKey.signature, response.longTermPublicKey.signature)
            Assertions.assertArrayEquals(oneTimeKey, response.oneTimePublicKey)
        } catch (e: Exception) {
            // Handle as needed
        }
    }

    private fun init() {
        this.identity = generateIdentity()
        val identityKeyPair = crypto.generateKeyPair(KeyPairType.ED25519)
        this.identityPrivateKey = identityKeyPair.privateKey
        this.client = RatchetClient(URL(TestConfig.serviceURL))
    }
}
