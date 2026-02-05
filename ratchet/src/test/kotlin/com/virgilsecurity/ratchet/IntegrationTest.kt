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

package com.virgilsecurity.ratchet

import com.virgilsecurity.ratchet.keystorage.FileLongTermKeysStorage
import com.virgilsecurity.ratchet.keystorage.FileOneTimeKeysStorage
import com.virgilsecurity.ratchet.securechat.SecureChat
import com.virgilsecurity.ratchet.securechat.SecureChatContext
import com.virgilsecurity.ratchet.sessionstorage.FileGroupSessionStorage
import com.virgilsecurity.ratchet.sessionstorage.FileSessionStorage
import com.virgilsecurity.sdk.crypto.KeyPairType
import com.virgilsecurity.sdk.crypto.VirgilCrypto
import com.virgilsecurity.sdk.crypto.VirgilPublicKey
import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.nio.file.Files

class IntegrationTest {

    private lateinit var crypto: VirgilCrypto
    private lateinit var senderIdentity: String
    private lateinit var senderIdentityPublicKey: VirgilPublicKey
    private lateinit var receiverIdentity: String
    private lateinit var receiverIdentityPublicKey: VirgilPublicKey
    private lateinit var senderSecureChat: SecureChat
    private lateinit var receiverSecureChat: SecureChat
    private lateinit var client: InMemoryRatchetClient

    @BeforeEach
    fun setup() {
        this.crypto = VirgilCrypto()

        init()
    }

    @Test
    fun encrypt_decrypt__random_uuid_messages__should_decrypt() {
        this.client.currentIdentity = this.receiverIdentity
        val rotationResult = this.receiverSecureChat.rotateKeys().get()
        this.client.uploadPublicKeys(rotationResult.longTermPublicKey, rotationResult.oneTimePublicKeys).execute()

        val senderSession = this.senderSecureChat.startNewSessionAsSender(this.receiverIdentity, this.receiverIdentityPublicKey).get()
        val plainText = generateText()
        val cipherText = senderSession.encrypt(plainText)

        val receiverSession = this.receiverSecureChat.startNewSessionAsReceiver(this.senderIdentity, this.senderIdentityPublicKey, cipherText)

        val decryptedMessage = receiverSession.decryptString(cipherText)
        Assertions.assertEquals(plainText, decryptedMessage)

        Utils.encryptDecrypt100Times(senderSession, receiverSession)
    }

    @Test
    fun session_persistence__random_uuid_messages__should_decrypt() {
        this.client.currentIdentity = this.receiverIdentity
        val rotationResult = this.receiverSecureChat.rotateKeys().get()
        this.client.uploadPublicKeys(rotationResult.longTermPublicKey, rotationResult.oneTimePublicKeys).execute()

        val senderSession = this.senderSecureChat.startNewSessionAsSender(this.receiverIdentity, this.receiverIdentityPublicKey).get()
        this.senderSecureChat.storeSession(senderSession)
        Assertions.assertNotNull(this.senderSecureChat.existingSession(this.receiverIdentity))

        val plainText = generateText()
        val cipherText = senderSession.encrypt(plainText)

        this.senderSecureChat.storeSession(senderSession)

        val receiverSession = this.receiverSecureChat.startNewSessionAsReceiver(this.senderIdentity, this.senderIdentityPublicKey, cipherText)
        this.receiverSecureChat.storeSession(receiverSession)
        Assertions.assertNotNull(this.receiverSecureChat.existingSession(this.senderIdentity))

        val decryptedMessage = receiverSession.decryptString(cipherText)
        this.receiverSecureChat.storeSession(receiverSession)
        Assertions.assertEquals(plainText, decryptedMessage)

        Utils.encryptDecrypt100TimesRestored(this.senderSecureChat, this.senderIdentity,
                this.receiverSecureChat, this.receiverIdentity)
    }

    @Test
    fun session_removal__one_session_per_participant__should_delete_session() {
        this.client.currentIdentity = this.receiverIdentity
        val rotationResult = this.receiverSecureChat.rotateKeys().get()
        this.client.uploadPublicKeys(rotationResult.longTermPublicKey, rotationResult.oneTimePublicKeys).execute()

        val senderSession = this.senderSecureChat.startNewSessionAsSender(this.receiverIdentity, this.receiverIdentityPublicKey).get()
        Assertions.assertNull(this.senderSecureChat.existingSession(this.receiverIdentity))

        senderSecureChat.storeSession(senderSession)
        Assertions.assertNotNull(this.senderSecureChat.existingSession(this.receiverIdentity))

        val plainText = generateText()
        val cipherText = senderSession.encrypt(plainText)

        val receiverSession = this.receiverSecureChat.startNewSessionAsReceiver(this.senderIdentity, this.senderIdentityPublicKey, cipherText)
        Assertions.assertNull(this.receiverSecureChat.existingSession(senderIdentity))

        this.receiverSecureChat.storeSession(receiverSession)
        Assertions.assertNotNull(this.receiverSecureChat.existingSession(senderIdentity))

        val decryptedMessage = receiverSession.decryptString(cipherText)
        Assertions.assertEquals(plainText, decryptedMessage)

        Utils.encryptDecrypt100Times(senderSession, receiverSession)

        this.senderSecureChat.deleteSession(receiverIdentity)
        this.receiverSecureChat.deleteSession(senderIdentity)

        Assertions.assertNull(this.senderSecureChat.existingSession(this.receiverIdentity))
        Assertions.assertNull(this.receiverSecureChat.existingSession(this.senderIdentity))
    }

    @Test
    fun reset__one_session_per_participant__should_reset() {
        this.client.currentIdentity = this.receiverIdentity
        var rotationResult = this.receiverSecureChat.rotateKeys().get()
        this.client.uploadPublicKeys(rotationResult.longTermPublicKey, rotationResult.oneTimePublicKeys).execute()

        this.client.currentIdentity = this.senderIdentity
        rotationResult = this.senderSecureChat.rotateKeys().get()
        this.client.uploadPublicKeys(rotationResult.longTermPublicKey, rotationResult.oneTimePublicKeys).execute()

        val senderSession = this.senderSecureChat.startNewSessionAsSender(this.receiverIdentity, this.receiverIdentityPublicKey).get()
        this.senderSecureChat.storeSession(senderSession)

        val plainText = generateText()
        val cipherText = senderSession.encrypt(plainText)

        val receiverSession = this.receiverSecureChat.startNewSessionAsReceiver(this.senderIdentity, this.senderIdentityPublicKey, cipherText)
        this.receiverSecureChat.storeSession(receiverSession)

        val decryptedMessage = receiverSession.decryptString(cipherText)
        Assertions.assertEquals(plainText, decryptedMessage)

        Utils.encryptDecrypt100Times(senderSession, receiverSession)

        this.client.currentIdentity = this.senderIdentity
        this.senderSecureChat.reset().execute()
        Assertions.assertNull(this.senderSecureChat.existingSession(this.receiverIdentity))
        Assertions.assertTrue(this.senderSecureChat.longTermKeysStorage.retrieveAllKeys().isEmpty())

        this.senderSecureChat.oneTimeKeysStorage.startInteraction()
        Assertions.assertTrue(this.senderSecureChat.oneTimeKeysStorage.retrieveAllKeys().isEmpty())
        this.senderSecureChat.oneTimeKeysStorage.stopInteraction()

        // Check that reset haven't affected receivers
        Assertions.assertNotNull(this.receiverSecureChat.existingSession(this.senderIdentity))

        this.client.currentIdentity = this.receiverIdentity
        this.receiverSecureChat.reset().execute()
        Assertions.assertNull(this.receiverSecureChat.existingSession(this.senderIdentity))
        Assertions.assertTrue(this.receiverSecureChat.longTermKeysStorage.retrieveAllKeys().isEmpty())

        receiverSecureChat.oneTimeKeysStorage.startInteraction()
        Assertions.assertTrue(this.receiverSecureChat.oneTimeKeysStorage.retrieveAllKeys().isEmpty())
        this.receiverSecureChat.oneTimeKeysStorage.stopInteraction()
    }

    @Test
    fun start_as_receiver__one_session__should_replenish_ot_key() {
        this.client.currentIdentity = this.receiverIdentity
        var rotationResult = this.receiverSecureChat.rotateKeys().get()
        this.client.uploadPublicKeys(rotationResult.longTermPublicKey, rotationResult.oneTimePublicKeys).execute()

        this.client.currentIdentity = this.senderIdentity
        rotationResult = this.senderSecureChat.rotateKeys().get()
        this.client.uploadPublicKeys(rotationResult.longTermPublicKey, rotationResult.oneTimePublicKeys).execute()

        this.receiverSecureChat.oneTimeKeysStorage.startInteraction()
        Assertions.assertEquals(IntegrationTest.DESIRED_NUMBER_OF_KEYS, this.receiverSecureChat.oneTimeKeysStorage.retrieveAllKeys().size)

        val senderSession = this.senderSecureChat.startNewSessionAsSender(this.receiverIdentity, this.receiverIdentityPublicKey).get()

        val plainText = generateText()
        val cipherText = senderSession.encrypt(plainText)

        this.client.currentIdentity = this.receiverIdentity
        this.receiverSecureChat.startNewSessionAsReceiver(this.senderIdentity, this.senderIdentityPublicKey, cipherText)

        Assertions.assertEquals(IntegrationTest.DESIRED_NUMBER_OF_KEYS, receiverSecureChat.oneTimeKeysStorage.retrieveAllKeys().size)

        this.receiverSecureChat.oneTimeKeysStorage.stopInteraction()
    }

    @Test
    fun rotate__double_rotate_empty_storage__should_complete() {
        this.client.currentIdentity = this.receiverIdentity
        var rotationResult = this.receiverSecureChat.rotateKeys().get()
        this.client.uploadPublicKeys(rotationResult.longTermPublicKey, rotationResult.oneTimePublicKeys).execute()

        rotationResult = this.receiverSecureChat.rotateKeys().get()
        this.client.uploadPublicKeys(rotationResult.longTermPublicKey, rotationResult.oneTimePublicKeys).execute()
    }

    @Test
    fun rotate__one_session__should_replenish_ot_key() {
        this.client.currentIdentity = this.receiverIdentity
        var rotationResult = this.receiverSecureChat.rotateKeys().get()
        this.client.uploadPublicKeys(rotationResult.longTermPublicKey, rotationResult.oneTimePublicKeys).execute()

        this.client.currentIdentity = this.senderIdentity
        rotationResult = this.senderSecureChat.rotateKeys().get()
        this.client.uploadPublicKeys(rotationResult.longTermPublicKey, rotationResult.oneTimePublicKeys).execute()

        this.receiverSecureChat.oneTimeKeysStorage.startInteraction()
        Assertions.assertEquals(IntegrationTest.DESIRED_NUMBER_OF_KEYS, receiverSecureChat.oneTimeKeysStorage.retrieveAllKeys().size)

        val senderSession = this.senderSecureChat.startNewSessionAsSender(this.receiverIdentity, this.receiverIdentityPublicKey).get()

        val plainText = generateText()
        val cipherText = senderSession.encrypt(plainText)

        this.client.currentIdentity = this.receiverIdentity
        rotationResult = this.receiverSecureChat.rotateKeys().get()
        this.client.uploadPublicKeys(rotationResult.longTermPublicKey, rotationResult.oneTimePublicKeys).execute()

        Assertions.assertEquals(IntegrationTest.DESIRED_NUMBER_OF_KEYS, receiverSecureChat.oneTimeKeysStorage.retrieveAllKeys().size)

        this.receiverSecureChat.oneTimeKeysStorage.stopInteraction()

        try {
            this.receiverSecureChat.startNewSessionAsReceiver(this.senderIdentity, this.senderIdentityPublicKey, cipherText)
            Assertions.fail<String>()
        } catch (e: Exception) {
        }
    }

    @Test
    fun rotate__ltk_outdated__should_outdate_and_delete_ltk() {
        this.client.currentIdentity = this.receiverIdentity
        var rotationResult = this.receiverSecureChat.rotateKeys().get()
        this.client.uploadPublicKeys(rotationResult.longTermPublicKey, rotationResult.oneTimePublicKeys).execute()

        Assertions.assertEquals(1, receiverSecureChat.longTermKeysStorage.retrieveAllKeys().size)

        Thread.sleep(11000)

        rotationResult = this.receiverSecureChat.rotateKeys().get()
        this.client.uploadPublicKeys(rotationResult.longTermPublicKey, rotationResult.oneTimePublicKeys).execute()
        Assertions.assertEquals(2, receiverSecureChat.longTermKeysStorage.retrieveAllKeys().size)

        Thread.sleep(5000)

        rotationResult = this.receiverSecureChat.rotateKeys().get()
        this.client.uploadPublicKeys(rotationResult.longTermPublicKey, rotationResult.oneTimePublicKeys).execute()
        Assertions.assertEquals(1, receiverSecureChat.longTermKeysStorage.retrieveAllKeys().size)
    }

    @Test
    fun start_multiple_chats__random_uuid_messages__should_decrypt() {
        val identity1 = senderIdentity
        val identity2 = receiverIdentity
        val pubKey1 = senderIdentityPublicKey
        val pubKey2 = receiverIdentityPublicKey
        val chat1 = senderSecureChat
        val chat2 = receiverSecureChat

        init()
        val identity3 = senderIdentity
        val pubKey3 = senderIdentityPublicKey
        val chat3 = senderSecureChat

        init()
        val identity4 = senderIdentity
        val pubKey4 = senderIdentityPublicKey
        val chat4 = senderSecureChat

        this.client.currentIdentity = identity2
        var rotationResult = chat2.rotateKeys().get()
        this.client.uploadPublicKeys(rotationResult.longTermPublicKey, rotationResult.oneTimePublicKeys).execute()

        this.client.currentIdentity = identity3
        rotationResult = chat3.rotateKeys().get()
        this.client.uploadPublicKeys(rotationResult.longTermPublicKey, rotationResult.oneTimePublicKeys).execute()

        this.client.currentIdentity = identity4
        rotationResult = chat4.rotateKeys().get()
        this.client.uploadPublicKeys(rotationResult.longTermPublicKey, rotationResult.oneTimePublicKeys).execute()

        val sessions = chat1.startMutipleNewSessionsAsSender(listOf(identity2, identity3, identity4), listOf(pubKey2, pubKey3, pubKey4)).get()

        val plainText2 = generateText()
        val plainText3 = generateText()
        val plainText4 = generateText()

        val cipherText2 = sessions[0].encrypt(plainText2)
        val cipherText3 = sessions[1].encrypt(plainText3)
        val cipherText4 = sessions[2].encrypt(plainText4)

        val receiverSession2 = chat2.startNewSessionAsReceiver(identity1, pubKey1, cipherText2)
        val receiverSession3 = chat3.startNewSessionAsReceiver(identity1, pubKey1, cipherText3)
        val receiverSession4 = chat4.startNewSessionAsReceiver(identity1, pubKey1, cipherText4)

        val decryptedMessage2 = receiverSession2.decryptString(cipherText2)
        val decryptedMessage3 = receiverSession3.decryptString(cipherText3)
        val decryptedMessage4 = receiverSession4.decryptString(cipherText4)

        Assertions.assertEquals(plainText2, decryptedMessage2)
        Assertions.assertEquals(plainText3, decryptedMessage3)
        Assertions.assertEquals(plainText4, decryptedMessage4)

        Utils.encryptDecrypt100Times(sessions[0], receiverSession2)
        Utils.encryptDecrypt100Times(sessions[1], receiverSession3)
        Utils.encryptDecrypt100Times(sessions[2], receiverSession4)
    }

    private fun init() {
        if (!::client.isInitialized) {
            this.client = InMemoryRatchetClient()
        }

        val senderIdentity = generateIdentity()
        val senderIdentityKeyPair = this.crypto.generateKeyPair(KeyPairType.ED25519)
        this.senderIdentity = senderIdentity
        this.senderIdentityPublicKey = senderIdentityKeyPair.publicKey

        val senderStore = client.UserStore()
        senderStore.identityPublicKey = senderIdentityKeyPair.publicKey
        senderStore.identityPublicKeyData = this.crypto.exportPublicKey(senderIdentityKeyPair.publicKey)
        client.users[senderIdentity] = senderStore

        val senderContext = SecureChatContext(senderIdentity, senderIdentityKeyPair,
                                              Files.createTempDirectory("testSender").toAbsolutePath().toString(),
                                              this.crypto, client)
        this.senderSecureChat = SecureChat(senderContext)

        val receiverIdentity = generateIdentity()
        val receiverIdentityKeyPair = this.crypto.generateKeyPair(KeyPairType.ED25519)
        this.receiverIdentity = receiverIdentity
        this.receiverIdentityPublicKey = receiverIdentityKeyPair.publicKey

        val receiverStore = client.UserStore()
        receiverStore.identityPublicKey = receiverIdentityKeyPair.publicKey
        receiverStore.identityPublicKeyData = this.crypto.exportPublicKey(receiverIdentityKeyPair.publicKey)
        client.users[receiverIdentity] = receiverStore

        val receiverContext = SecureChatContext(receiverIdentity, receiverIdentityKeyPair,
                                                Files.createTempDirectory("testReceiver").toAbsolutePath().toString(),
                                                this.crypto, client)
        this.receiverSecureChat = SecureChat(receiverContext)
    }

    companion object {
        private const val DESIRED_NUMBER_OF_KEYS = 5
    }
}
