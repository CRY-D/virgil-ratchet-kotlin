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

package com.virgilsecurity.ratchet.demo

import com.virgilsecurity.ratchet.client.data.PublicKeySet
import com.virgilsecurity.ratchet.securechat.RatchetParticipant
import com.virgilsecurity.ratchet.securechat.SecureChat
import com.virgilsecurity.ratchet.securechat.SecureChatContext
import com.virgilsecurity.sdk.crypto.KeyPairType
import com.virgilsecurity.sdk.crypto.VirgilCrypto
import com.virgilsecurity.sdk.crypto.VirgilKeyPair
import java.io.File
import java.nio.file.Files

/**
 * A simple command-line demo showing how two participants (Alice and Bob)
 * can exchange encrypted messages using the decoupled Virgil Ratchet SDK.
 */
fun main(args: Array<String>) {
    val crypto = VirgilCrypto()

    println("--- Starting Standalone CLI Demo ---")

    // 1. Initialize Alice's environment
    val aliceIdentity = "Alice"
    val aliceKeyPair = crypto.generateKeyPair(KeyPairType.ED25519)
    val aliceChat = createSecureChat(crypto, aliceIdentity, aliceKeyPair)
    println("[Alice] Initialized")

    // 2. Initialize Bob's environment
    val bobIdentity = "Bob"
    val bobKeyPair = crypto.generateKeyPair(KeyPairType.ED25519)
    val bobChat = createSecureChat(crypto, bobIdentity, bobKeyPair)
    println("[Bob] Initialized")

    // 3. Bob rotates keys to generate LTK and OTKs for Alice to use
    val bobRotationResult = bobChat.rotateKeys().get()
    println("[Bob] Generated rotation keys (LTK and ${bobRotationResult.oneTimePublicKeys.size} OTKs)")

    // SIMULATION: Bob "publishes" his keys to a signaling server, and Alice "fetches" them.
    val bobPublicKeySet = PublicKeySet(
        identityPublicKey = crypto.exportPublicKey(bobKeyPair.publicKey),
        longTermPublicKey = bobRotationResult.longTermPublicKey!!,
        oneTimePublicKey = bobRotationResult.oneTimePublicKeys.first() // Alice uses one OTK
    )
    println("[System] Alice fetched Bob's public key set")

    // 4. Alice starts a session with Bob
    val aliceSession = aliceChat.startNewSessionAsSender(
        receiverIdentity = bobIdentity,
        receiverIdentityPublicKey = bobKeyPair.publicKey,
        publicKeySet = bobPublicKeySet
    )
    println("[Alice] Started new session with Bob")

    // 5. Alice encrypts and "sends" a message to Bob
    val messageText = "Hello Bob! This is a secure message from the CLI demo."
    val encryptedMessage = aliceSession.encrypt(messageText)
    aliceChat.storeSession(aliceSession) // Important: store state change
    println("[Alice] Encrypted message: '${messageText}'")

    // 6. Bob receives the first message (PREKEY message) and establishes his session
    val bobSession = bobChat.startNewSessionAsReceiver(
        senderIdentity = aliceIdentity,
        senderIdentityPublicKey = aliceKeyPair.publicKey,
        ratchetMessage = encryptedMessage
    )
    println("[Bob] Received PREKEY message and established session with Alice")

    // 7. Bob decrypts Alice's message
    val decryptedText = bobSession.decryptString(encryptedMessage)
    bobChat.storeSession(bobSession) // Important: store state change
    println("[Bob] Decrypted message: '${decryptedText}'")

    if (messageText == decryptedText) {
        println("--- P2P Demo Successful! ---")
    } else {
        println("--- P2P Demo Failed! ---")
        return
    }

    // --- Group Chat Demo ---
    println("\n--- Starting Group Chat Demo ---")

    val carolIdentity = "Carol"
    val carolKeyPair = crypto.generateKeyPair(KeyPairType.ED25519)
    val carolChat = createSecureChat(crypto, carolIdentity, carolKeyPair)
    val carolIdInGroup = crypto.generateRandomData(32)
    println("[Carol] Initialized")

    val aliceIdInGroup = crypto.generateRandomData(32)
    val bobIdInGroup = crypto.generateRandomData(32)

    // Alice creates a group chat
    val sessionId = crypto.generateRandomData(32)
    val ticket = aliceChat.startNewGroupSession(sessionId)

    // Alice defines participants (excluding herself)
    val groupParticipants = listOf(
        RatchetParticipant(bobIdentity, bobKeyPair.publicKey, bobIdInGroup),
        RatchetParticipant(carolIdentity, carolKeyPair.publicKey, carolIdInGroup)
    )

    val aliceGroupSession = aliceChat.startGroupSession(groupParticipants, sessionId, ticket, aliceIdInGroup)
    aliceChat.storeGroupSession(aliceGroupSession)
    println("[Alice] Created group session")

    // Simulation: Alice sends the ticket and participant info to Bob and Carol
    // Bob joins
    val bobGroupParticipants = listOf(
        RatchetParticipant(aliceIdentity, aliceKeyPair.publicKey, aliceIdInGroup),
        RatchetParticipant(carolIdentity, carolKeyPair.publicKey, carolIdInGroup)
    )
    val bobGroupSession = bobChat.startGroupSession(bobGroupParticipants, sessionId, ticket, bobIdInGroup)
    bobChat.storeGroupSession(bobGroupSession)
    println("[Bob] Joined group session")

    // Alice sends a group message
    val groupMsgText = "Hey team, this group chat is totally independent of Virgil Cloud!"
    val encryptedGroupMsg = aliceGroupSession.encrypt(groupMsgText)
    aliceChat.storeGroupSession(aliceGroupSession)
    println("[Alice] Sent group message")

    // Bob decrypts it
    val bobDecryptedGroupMsg = bobGroupSession.decryptString(encryptedGroupMsg, aliceIdInGroup)
    bobChat.storeGroupSession(bobGroupSession)
    println("[Bob] Decrypted group message: '${bobDecryptedGroupMsg}'")

    println("--- Group Demo Successful! ---")
}

private fun createSecureChat(crypto: VirgilCrypto, identity: String, keyPair: VirgilKeyPair): SecureChat {
    val tempDir = Files.createTempDirectory("ratchet-demo-$identity").toFile()
    val context = SecureChatContext(
        identity = identity,
        identityKeyPair = keyPair,
        rootPath = tempDir.absolutePath,
        virgilCrypto = crypto,
        ratchetClient = null // Manual key exchange
    )
    return SecureChat(context)
}
