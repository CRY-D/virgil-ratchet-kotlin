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

import com.virgilsecurity.crypto.ratchet.RatchetException
import com.virgilsecurity.ratchet.keystorage.FileLongTermKeysStorage
import com.virgilsecurity.ratchet.keystorage.FileOneTimeKeysStorage
import com.virgilsecurity.ratchet.securechat.*
import com.virgilsecurity.ratchet.sessionstorage.FileGroupSessionStorage
import com.virgilsecurity.ratchet.sessionstorage.FileSessionStorage
import com.virgilsecurity.sdk.crypto.KeyPairType
import com.virgilsecurity.sdk.crypto.VirgilCrypto
import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.nio.file.Files

class GroupIntegrationTest {

    private lateinit var crypto: VirgilCrypto
    private lateinit var participants: MutableList<RatchetParticipant>
    private lateinit var chats: MutableList<SecureChat>
    private lateinit var client: InMemoryRatchetClient

    @BeforeEach
    fun setup() {
        this.crypto = VirgilCrypto()
    }

    private fun init(numberOfParticipants: Int) {
        if (!::client.isInitialized) {
            this.client = InMemoryRatchetClient()
        }

        this.participants = mutableListOf()
        this.chats = mutableListOf()

        for (i in 0 until numberOfParticipants) {
            val identity = generateIdentity()
            val keyPair = this.crypto.generateKeyPair(KeyPairType.ED25519)
            val identifier = this.crypto.generateRandomData(32)

            val participant = RatchetParticipant(identity, keyPair.publicKey, identifier)

            val userStore = client.UserStore()
            userStore.identityPublicKey = keyPair.publicKey
            userStore.identityPublicKeyData = this.crypto.exportPublicKey(keyPair.publicKey)
            client.users[identity] = userStore

            val longTermKeysStorage =
                    FileLongTermKeysStorage(identity, this.crypto, keyPair, Files.createTempDirectory("test").toAbsolutePath().toString())
            val oneTimeKeysStorage = FileOneTimeKeysStorage(identity, this.crypto, keyPair)

            val secureChat = SecureChat(
                    SecureChatContext(identity, keyPair, Files.createTempDirectory("test").toAbsolutePath().toString(), this.crypto, client)
            )

            this.participants.add(participant)
            this.chats.add(secureChat)
        }
    }

    @Test
    fun encrypt_decrypt__random_uuid_messages__should_decrypt() {
        val num = 10

        init(num)
        val participants1 = this.participants
        val chats1 = this.chats

        val sessionId = this.crypto.generateRandomData(32)
        val initMsg = chats1.first().startNewGroupSession(sessionId)

        var sessions = mutableListOf<SecureGroupSession>()

        for (i in 0 until num) {
            val localParticipants = participants1.toMutableList()
            localParticipants.removeAt(i)

            val session = chats1[i].startGroupSession(localParticipants, sessionId, initMsg, participants1[i].identifier)
            sessions.add(session)
        }

        Utils.encryptDecrypt100Times(sessions)

        init(num)
        val participants2 = this.participants
        val chats2 = this.chats

        val ticket1 = sessions[0].createChangeParticipantsTicket()

        for (i in 0 until num * 2) {
            if (i < num) {
                sessions[i].updateParticipants(ticket1, participants2, listOf())
            } else {
                val localParticipants = participants2.toMutableList()
                localParticipants.removeAt(i - num)

                val session = chats2[i - num].startGroupSession(participants1 + localParticipants, sessionId, ticket1, participants2[i - num].identifier)

                sessions.add(session)
            }
        }

        Utils.encryptDecrypt100Times(sessions)

        init(num)
        val participants3 = this.participants
        val chats3 = this.chats

        val ticket2 = sessions[num].createChangeParticipantsTicket()
        sessions = sessions.subList(num, sessions.size)

        for (i in 0 until num * 2) {
            if (i < num) {
                sessions[i].updateParticipants(ticket2, participants3, participants1.map { it.identifier })
            } else {
                val localParticipants = participants3.toMutableList()
                localParticipants.removeAt(i - num)

                val session = chats3[i - num].startGroupSession(participants2 + localParticipants, sessionId, ticket2, participants3[i - num].identifier)

                sessions.add(session)
            }
        }

        Utils.encryptDecrypt100Times(sessions)
    }

    @Test
    fun decrypt__old_session_messages__should_not_crash() {
        val num = 3
        init(num)

        val sessionId = this.crypto.generateRandomData(32)
        val initMsg = this.chats.first().startNewGroupSession(sessionId)

        var sessions = mutableListOf<SecureGroupSession>()

        for (i in 0 until num) {
            val localParticipants = participants.toMutableList()
            localParticipants.removeAt(i)

            val session = chats[i].startGroupSession(localParticipants, sessionId, initMsg, participants[i].identifier)
            sessions.add(session)
        }

        // Encrypt plaintext
        val plainText = generateText()
        val message = sessions.first().encrypt(plainText)
        val decryptedMessage1 = sessions.last().decryptString(message, participants[0].identifier)
        Assertions.assertEquals(plainText, decryptedMessage1)

        // Remove user
        val experimentalParticipant = participants.last()
        val removeParticipantIds = listOf(experimentalParticipant.identifier)

        val removeTicket = sessions.first().createChangeParticipantsTicket()
        sessions.removeAt(sessions.size - 1)

        sessions.forEach { session ->
            session.updateParticipants(removeTicket, listOf(), removeParticipantIds)
        }

        // Return user
        val addTicket = sessions.first().createChangeParticipantsTicket()

        sessions.forEach { session ->
            session.updateParticipants(addTicket, listOf(), listOf()) // wait, I should add the user back
            session.updateParticipants(addTicket, listOf(experimentalParticipant), listOf())
        }

        val newSession = chats.last().startGroupSession(participants.dropLast(1), sessionId, addTicket, experimentalParticipant.identifier)
        sessions.add(newSession)

        // Decrypt with new session message, encrypted for old session
        try {
            sessions.last().decryptString(message, participants[0].identifier)
        } catch (e: RatchetException) {
            Assertions.assertEquals(RatchetException.ERROR_EPOCH_NOT_FOUND, e.statusCode)
        }
    }

    @Test
    fun add_remove__user_100_times__should_not_crash() {
        val num = 3
        init(num)

        val sessionId = this.crypto.generateRandomData(32)
        val initMsg = this.chats.first().startNewGroupSession(sessionId)

        var sessions = mutableListOf<SecureGroupSession>()

        for (i in 0 until num) {
            val localParticipants = participants.toMutableList()
            localParticipants.removeAt(i)

            val session = chats[i].startGroupSession(localParticipants, sessionId, initMsg, participants[i].identifier)
            sessions.add(session)
        }

        for (i in 1 until 100) {
            // Remove user
            val experimentalParticipant = participants.last()
            val removeParticipantIds = listOf(experimentalParticipant.identifier)

            val removeTicket = sessions.first().createChangeParticipantsTicket()

            sessions.removeAt(sessions.size - 1)

            sessions.forEach { session ->
                session.updateParticipants(removeTicket, listOf(), removeParticipantIds)
            }

            // Return user
            val addTicket = sessions.first().createChangeParticipantsTicket()

            sessions.forEach { session ->
                session.updateParticipants(addTicket, listOf(experimentalParticipant), listOf())
            }

            val newSession = this.chats.last().startGroupSession(participants.dropLast(1), sessionId, addTicket, experimentalParticipant.identifier)
            sessions.add(newSession)
        }
    }

    @Test
    fun decrypt__wrong_sender__should_return_error() {
        val num = 3
        init(num)

        val sessionId = this.crypto.generateRandomData(32)
        val initMsg = this.chats.first().startNewGroupSession(sessionId)

        val sessions = mutableListOf<SecureGroupSession>()

        for (i in 0 until num) {
            val localParticipants = participants.toMutableList()
            localParticipants.removeAt(i)

            val session = chats[i].startGroupSession(localParticipants, sessionId, initMsg, participants[i].identifier)
            sessions.add(session)
        }

        val str = generateText()
        val message = sessions[0].encrypt(str)

        val decrypted = sessions[1].decryptString(message, sessions[0].myIdentifier())
        Assertions.assertEquals(str, decrypted)

        val crypto = VirgilCrypto()

        try {
            sessions[1].decryptString(message, sessions[2].myIdentifier())
            Assertions.fail<String>()
        } catch (e: RatchetException) {
            Assertions.assertEquals(RatchetException.ERROR_INVALID_SIGNATURE, e.statusCode)
        }

        try {
            val randomId = crypto.generateRandomData(32)
            sessions[1].decryptString(message, randomId)
            Assertions.fail<String>()
        } catch (e: RatchetException) {
            Assertions.assertEquals(RatchetException.ERROR_SENDER_NOT_FOUND, e.statusCode)
        }
    }

    @Test
    fun session_persistence__random_uuid_messages__should_decrypt() {
        val num = 10
        init(num)

        val sessionId = this.crypto.generateRandomData(32)
        val initMsg = this.chats.first().startNewGroupSession(sessionId)

        var sessions = mutableListOf<SecureGroupSession>()

        for (i in 0 until num) {
            val localParticipants = this.participants.toMutableList()
            localParticipants.removeAt(i)

            val session = this.chats[i].startGroupSession(localParticipants, sessionId, initMsg, participants[i].identifier)
            sessions.add(session)

            this.chats[i].storeGroupSession(session)
        }

        Utils.encryptDecrypt100TimesRestored(this.chats, sessions[0].identifier())
    }

    companion object {
        private const val DESIRED_NUMBER_OF_KEYS = 5
    }
}
