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

import com.virgilsecurity.crypto.ratchet.RatchetMessage
import com.virgilsecurity.ratchet.client.data.PublicKeySet
import com.virgilsecurity.ratchet.securechat.RatchetParticipant
import com.virgilsecurity.ratchet.securechat.SecureChat
import com.virgilsecurity.ratchet.securechat.SecureChatContext
import com.virgilsecurity.sdk.crypto.KeyPairType
import com.virgilsecurity.sdk.crypto.VirgilCrypto
import com.virgilsecurity.sdk.crypto.VirgilKeyPair
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test
import java.nio.file.Files

/**
 * This class demonstrates how to use the SDK without Virgil Cloud/Cards.
 */
class DemoUsage {

    private val crypto = VirgilCrypto()

    @Test
    fun peer_to_peer_demo() {
        // 1. Initialize Alice's SecureChat
        val aliceIdentity = "Alice"
        val aliceKeyPair = crypto.generateKeyPair(KeyPairType.ED25519)
        val aliceChat = createSecureChat(aliceIdentity, aliceKeyPair)

        // 2. Initialize Bob's SecureChat
        val bobIdentity = "Bob"
        val bobKeyPair = crypto.generateKeyPair(KeyPairType.ED25519)
        val bobChat = createSecureChat(bobIdentity, bobKeyPair)

        // 3. Bob generates his keys for exchange (LTK, OTKs)
        val bobRotationResult = bobChat.rotateKeys().get()
        // In a real app, Bob would send these to Alice via a signaling server
        val bobPublicKeySet = PublicKeySet(
            identityPublicKey = crypto.exportPublicKey(bobKeyPair.publicKey),
            longTermPublicKey = bobRotationResult.longTermPublicKey!!,
            oneTimePublicKey = bobRotationResult.oneTimePublicKeys.first()
        )

        // 4. Alice starts a session with Bob using his public keys
        val aliceSession = aliceChat.startNewSessionAsSender(
            receiverIdentity = bobIdentity,
            receiverIdentityPublicKey = bobKeyPair.publicKey,
            publicKeySet = bobPublicKeySet
        )

        // 5. Alice encrypts a message
        val messageText = "Hello Bob! This is Alice."
        val encryptedMessage = aliceSession.encrypt(messageText)
        aliceChat.storeSession(aliceSession)

        // 6. Bob receives the message and starts a session as receiver
        val bobSession = bobChat.startNewSessionAsReceiver(
            senderIdentity = aliceIdentity,
            senderIdentityPublicKey = aliceKeyPair.publicKey,
            ratchetMessage = encryptedMessage
        )

        // 7. Bob decrypts the message
        val decryptedText = bobSession.decryptString(encryptedMessage)
        bobChat.storeSession(bobSession)

        assertEquals(messageText, decryptedText)
        println("P2P Demo Success: Decrypted message: $decryptedText")
    }

    @Test
    fun group_chat_demo() {
        // 1. Setup Alice, Bob, and Carol
        val aliceKeyPair = crypto.generateKeyPair(KeyPairType.ED25519)
        val aliceChat = createSecureChat("Alice", aliceKeyPair)
        val aliceIdInGroup = crypto.generateRandomData(32)

        val bobKeyPair = crypto.generateKeyPair(KeyPairType.ED25519)
        val bobChat = createSecureChat("Bob", bobKeyPair)
        val bobIdInGroup = crypto.generateRandomData(32)

        val carolKeyPair = crypto.generateKeyPair(KeyPairType.ED25519)
        val carolChat = createSecureChat("Carol", carolKeyPair)
        val carolIdInGroup = crypto.generateRandomData(32)

        // 2. Alice starts a group session
        val sessionId = crypto.generateRandomData(32)
        val ticket = aliceChat.startNewGroupSession(sessionId)

        // Participants list (excluding Alice herself for the startGroupSession call)
        val participants = listOf(
            RatchetParticipant("Bob", bobKeyPair.publicKey, bobIdInGroup),
            RatchetParticipant("Carol", carolKeyPair.publicKey, carolIdInGroup)
        )

        val aliceGroupSession = aliceChat.startGroupSession(participants, sessionId, ticket, aliceIdInGroup)
        aliceChat.storeGroupSession(aliceGroupSession)

        // 3. Bob joins the group session
        // In a real app, Alice sends the 'ticket' and 'participants' info to Bob (e.g. encrypted via P2P session)
        val bobParticipants = listOf(
            RatchetParticipant("Alice", aliceKeyPair.publicKey, aliceIdInGroup),
            RatchetParticipant("Carol", carolKeyPair.publicKey, carolIdInGroup)
        )
        val bobGroupSession = bobChat.startGroupSession(bobParticipants, sessionId, ticket, bobIdInGroup)
        bobChat.storeGroupSession(bobGroupSession)

        // 4. Alice sends a group message
        val groupMsgText = "Hi everyone!"
        val encryptedGroupMsg = aliceGroupSession.encrypt(groupMsgText)
        aliceChat.storeGroupSession(aliceGroupSession)

        // 5. Bob decrypts the group message
        val decryptedGroupMsg = bobGroupSession.decryptString(encryptedGroupMsg, aliceIdInGroup)
        bobChat.storeGroupSession(bobGroupSession)

        assertEquals(groupMsgText, decryptedGroupMsg)
        println("Group Demo Success: Decrypted message: $decryptedGroupMsg")
    }

    private fun createSecureChat(identity: String, keyPair: VirgilKeyPair): SecureChat {
        val rootPath = Files.createTempDirectory("ratchet-demo-$identity").toAbsolutePath().toString()
        val context = SecureChatContext(
            identity = identity,
            identityKeyPair = keyPair,
            rootPath = rootPath,
            virgilCrypto = crypto,
            ratchetClient = null // No client needed if you manage key exchange yourself
        )
        return SecureChat(context)
    }
}
