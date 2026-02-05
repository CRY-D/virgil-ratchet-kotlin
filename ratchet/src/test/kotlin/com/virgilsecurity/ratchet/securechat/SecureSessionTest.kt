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

package com.virgilsecurity.ratchet.securechat

import com.virgilsecurity.ratchet.*
import com.virgilsecurity.ratchet.exception.SecureChatException
import com.virgilsecurity.ratchet.securechat.keysrotation.KeysRotator
import com.virgilsecurity.sdk.crypto.KeyPairType
import com.virgilsecurity.sdk.crypto.VirgilPublicKey
import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test

class SecureSessionTest {

    private lateinit var senderIdentity: String
    private lateinit var senderIdentityPublicKey: VirgilPublicKey
    private lateinit var receiverIdentity: String
    private lateinit var receiverIdentityPublicKey: VirgilPublicKey
    private lateinit var senderSecureChat: SecureChat
    private lateinit var receiverSecureChat: SecureChat
    private lateinit var fakeClient: InMemoryRatchetClient

    @BeforeEach
    fun setup() {
        val crypto = TestConfig.virgilCrypto
        val receiverIdentityKeyPair = crypto.generateKeyPair(KeyPairType.ED25519)
        val senderIdentityKeyPair = crypto.generateKeyPair(KeyPairType.ED25519)

        this.senderIdentity = generateIdentity()
        this.receiverIdentity = generateIdentity()
        this.senderIdentityPublicKey = senderIdentityKeyPair.publicKey
        this.receiverIdentityPublicKey = receiverIdentityKeyPair.publicKey

        this.fakeClient = InMemoryRatchetClient()

        val senderStore = fakeClient.UserStore()
        senderStore.identityPublicKey = senderIdentityKeyPair.publicKey
        senderStore.identityPublicKeyData = crypto.exportPublicKey(senderIdentityKeyPair.publicKey)
        fakeClient.users[senderIdentity] = senderStore

        val receiverStore = fakeClient.UserStore()
        receiverStore.identityPublicKey = receiverIdentityKeyPair.publicKey
        receiverStore.identityPublicKeyData = crypto.exportPublicKey(receiverIdentityKeyPair.publicKey)
        fakeClient.users[receiverIdentity] = receiverStore

        this.senderSecureChat = SecureChat(
                crypto, senderIdentityKeyPair.privateKey, senderIdentity,
                fakeClient, InMemoryLongTermKeysStorage(),
                InMemoryOneTimeKeysStorage(), InMemorySessionStorage(), InMemoryGroupSessionStorage(),
                FakeKeysRotator()
        )

        val receiverLongTermKeysStorage = InMemoryLongTermKeysStorage()
        val receiverOneTimeKeysStorage = InMemoryOneTimeKeysStorage()

        val receiverKeysRotator = KeysRotator(
                crypto, receiverIdentityKeyPair.privateKey, 100,
                100, 100, 10, receiverLongTermKeysStorage,
                receiverOneTimeKeysStorage, fakeClient
        )

        this.receiverSecureChat = SecureChat(
                crypto, receiverIdentityKeyPair.privateKey,
                receiverIdentity, fakeClient, receiverLongTermKeysStorage,
                receiverOneTimeKeysStorage, InMemorySessionStorage(),
                InMemoryGroupSessionStorage(), receiverKeysRotator
        )
    }

    @Test
    fun encrypt_decrypt__random_uuid_messages_ram_client__should_decrypt() {
        this.fakeClient.currentIdentity = this.receiverIdentity
        val rotationResult = this.receiverSecureChat.rotateKeys().get()
        this.fakeClient.uploadPublicKeys(rotationResult.longTermPublicKey, rotationResult.oneTimePublicKeys).execute()

        val senderSession = this.senderSecureChat.startNewSessionAsSender(receiverIdentity, receiverIdentityPublicKey).get()

        val plainText = generateText()
        val cipherText = senderSession.encrypt(plainText)

        val receiverSession = this.receiverSecureChat.startNewSessionAsReceiver(senderIdentity, senderIdentityPublicKey, cipherText)
        val decryptedMessage = receiverSession.decryptString(cipherText)

        Assertions.assertEquals(plainText, decryptedMessage)

        Utils.encryptDecrypt100Times(senderSession, receiverSession)
    }

    @Test
    fun session_persistence__random_uuid_messages_ram_client__should_decrypt() {
        this.fakeClient.currentIdentity = this.receiverIdentity
        val rotationResult = this.receiverSecureChat.rotateKeys().get()
        this.fakeClient.uploadPublicKeys(rotationResult.longTermPublicKey, rotationResult.oneTimePublicKeys).execute()

        val senderSession = this.senderSecureChat.startNewSessionAsSender(this.receiverIdentity, receiverIdentityPublicKey).get()
        this.senderSecureChat.storeSession(senderSession)

        Assertions.assertNotNull(this.senderSecureChat.existingSession(this.receiverIdentity))

        val plainText = generateText()
        val cipherText = senderSession.encrypt(plainText)

        val receiverSession = this.receiverSecureChat.startNewSessionAsReceiver(this.senderIdentity, senderIdentityPublicKey, cipherText)
        this.receiverSecureChat.storeSession(receiverSession)

        Assertions.assertNotNull(this.receiverSecureChat.existingSession(this.senderIdentity))

        val decryptedMessage = receiverSession.decryptString(cipherText)

        Assertions.assertEquals(plainText, decryptedMessage)

        Utils.encryptDecrypt100TimesRestored(
                this.senderSecureChat,
                this.senderIdentity,
                this.receiverSecureChat,
                this.receiverIdentity
        )
    }

    @Test
    fun session_persistence__recreate_session__should_throw_error() {
        this.fakeClient.currentIdentity = this.receiverIdentity
        val rotationResult = this.receiverSecureChat.rotateKeys().get()
        this.fakeClient.uploadPublicKeys(rotationResult.longTermPublicKey, rotationResult.oneTimePublicKeys).execute()

        val senderSession = senderSecureChat.startNewSessionAsSender(receiverIdentity, receiverIdentityPublicKey).get()
        this.senderSecureChat.storeSession(senderSession)

        val plainText = generateText()
        val cipherText = senderSession.encrypt(plainText)

        val receiverSession = this.receiverSecureChat.startNewSessionAsReceiver(senderIdentity, senderIdentityPublicKey, cipherText)
        this.receiverSecureChat.storeSession(receiverSession)

        try {
            this.senderSecureChat.startNewSessionAsSender(receiverIdentity, receiverIdentityPublicKey).get()
            Assertions.fail<String>()
        } catch (e: SecureChatException) {
            Assertions.assertEquals(SecureChatException.SESSION_ALREADY_EXISTS, e.errorCode)
        } catch (e: Exception) {
            Assertions.fail<String>()
        }

        try {
            this.senderSecureChat.startNewSessionAsReceiver(receiverIdentity, receiverIdentityPublicKey, cipherText)
            Assertions.fail<String>()
        } catch (e: SecureChatException) {
            Assertions.assertEquals(SecureChatException.SESSION_ALREADY_EXISTS, e.errorCode)
        } catch (e: Exception) {
            Assertions.fail<String>()
        }

        try {
            this.receiverSecureChat.startNewSessionAsSender(senderIdentity, senderIdentityPublicKey).get()
            Assertions.fail<String>()
        } catch (e: SecureChatException) {
            Assertions.assertEquals(SecureChatException.SESSION_ALREADY_EXISTS, e.errorCode)
        } catch (e: Exception) {
            Assertions.fail<String>()
        }
        try {
            this.receiverSecureChat.startNewSessionAsReceiver(senderIdentity, senderIdentityPublicKey, cipherText)
            Assertions.fail<String>()
        } catch (e: SecureChatException) {
            Assertions.assertEquals(SecureChatException.SESSION_ALREADY_EXISTS, e.errorCode)
        } catch (e: Exception) {
            Assertions.fail<String>()
        }
    }
}
