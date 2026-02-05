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

import com.virgilsecurity.crypto.ratchet.*
import com.virgilsecurity.ratchet.exception.SecureGroupSessionException
import com.virgilsecurity.ratchet.utils.hexEncodedString
import com.virgilsecurity.sdk.crypto.VirgilCrypto
import com.virgilsecurity.sdk.crypto.VirgilPublicKey
import java.nio.charset.StandardCharsets

class SecureGroupSession {

    val crypto: VirgilCrypto
    val ratchetGroupSession: RatchetGroupSession
    val syncObj = 1

    constructor(
            crypto: VirgilCrypto,
            privateKeyData: ByteArray,
            myId: ByteArray,
            ratchetGroupMessage: RatchetGroupMessage,
            participants: List<RatchetParticipant>
    ) {
        this.crypto = crypto

        this.ratchetGroupSession = RatchetGroupSession()
        this.ratchetGroupSession.setRng(crypto.rng)
        this.ratchetGroupSession.setPrivateKey(privateKeyData)
        this.ratchetGroupSession.myId = myId

        val info = RatchetGroupParticipantsInfo(participants.size.toLong())

        participants.forEach { participant ->
            val participantId = participant.identifier
            val publicKeyData = this.crypto.exportPublicKey(participant.publicKey)

            info.addParticipant(participantId, publicKeyData)
        }
        this.ratchetGroupSession.setupSessionState(ratchetGroupMessage, info)
    }

    /**
     * Init session from serialized representation.
     *
     * @param data Serialized session.
     * @param privateKeyData Private key data.
     * @param crypto VirgilCrypto.
     */
    constructor(data: ByteArray, privateKeyData: ByteArray, crypto: VirgilCrypto) {
        this.crypto = crypto

        this.ratchetGroupSession = RatchetGroupSession.deserialize(data)
        this.ratchetGroupSession.setRng(crypto.rng)
        this.ratchetGroupSession.setPrivateKey(privateKeyData)
    }

    /**
     * Session id.
     */
    fun identifier(): ByteArray {
        return this.ratchetGroupSession.sessionId
    }

    /**
     * User identifier.
     */
    fun myIdentifier(): ByteArray {
        return this.ratchetGroupSession.myId
    }

    /**
     * Number of participants.
     */
    fun participantsCount(): Long {
        return this.ratchetGroupSession.participantsCount
    }

    fun currentEpoch(): Long {
        return this.ratchetGroupSession.currentEpoch
    }

    /**
     * Encrypts string.
     * This operation changes session state, so session should be updated in storage.
     *
     * @param string Message to encrypt.
     * @return RatchetMessage.
     */
    fun encrypt(string: String): RatchetGroupMessage {
        val data = string.toByteArray(StandardCharsets.UTF_8)
        return this.encrypt(data)
    }

    /**
     * Encrypts data.
     * This operation changes session state, so session should be updated in storage.
     *
     * @param data Message to encrypt.
     * @return RatchetMessage.
     */
    fun encrypt(data: ByteArray): RatchetGroupMessage {
        synchronized(syncObj) {
            return ratchetGroupSession.encrypt(data)
        }
    }

    /**
     * Decrypts data from RatchetMessage.
     * This operation changes session state, so session should be updated in storage.
     *
     * @param message RatchetGroupMessage.
     * @param senderId Sender id.
     * @return Decrypted data.
     */
    fun decryptData(message: RatchetGroupMessage, senderId: ByteArray): ByteArray {
        if (message.type != GroupMsgType.REGULAR) {
            throw SecureGroupSessionException(SecureGroupSessionException.INVALID_MESSAGE_TYPE, "Message should be a REGULAR type")
        }

        synchronized(syncObj) {
            return this.ratchetGroupSession.decrypt(message, senderId)
        }
    }

    /**
     * Decrypts utf-8 string from RatchetMessage.
     * This operation changes session state, so session should be updated in storage.
     *
     * @param message RatchetGroupMessage.
     * @param senderId Sender id.
     * @return Decrypted utf-8 string.
     */
    fun decryptString(message: RatchetGroupMessage, senderId: ByteArray): String {
        val data = this.decryptData(message, senderId)
        return data.toString(StandardCharsets.UTF_8)
    }

    /**
     * Creates ticket for adding/removing participants, or just to rotate secret.
     */
    fun createChangeParticipantsTicket(): RatchetGroupMessage {
        return this.ratchetGroupSession.createGroupTicket().ticketMessage
    }

    /**
     * Sets participants.
     *
     * @param ticket Ticket.
     * @param participants Participants to set.
     */
    fun setParticipants(ticket: RatchetGroupMessage, participants: List<RatchetParticipant>) {
        if (ticket.type != GroupMsgType.GROUP_INFO) {
            throw SecureGroupSessionException(SecureGroupSessionException.INVALID_MESSAGE_TYPE, "Ticket should be a GROUP_INFO type")
        }

        val info = RatchetGroupParticipantsInfo(participants.size.toLong())

        participants.forEach { participant ->
            val participantId = participant.identifier
            val publicKeyData = this.crypto.exportPublicKey(participant.publicKey)

            info.addParticipant(participantId, publicKeyData)
        }
        this.ratchetGroupSession.setupSessionState(ticket, info)
    }

    /**
     * Updates participants incrementally.
     *
     * NOTE: As this update is incremental, tickets should be applied strictly consequently.
     * NOTE: This operation changes session state, so session should be updated in storage.
     * Otherwise, use setParticipants().
     *
     * @param ticket Ticket.
     * @param addParticipants Participants to add.
     * @param removeParticipantIds Participants to remove.
     */
    fun updateParticipants(ticket: RatchetGroupMessage,
                           addParticipants: List<RatchetParticipant>,
                           removeParticipantIds: List<ByteArray>) {
        if (ticket.type != GroupMsgType.GROUP_INFO) {
            throw SecureGroupSessionException(SecureGroupSessionException.INVALID_MESSAGE_TYPE, "Ticket should be a GROUP_INFO type")
        }
        if (ticket.epoch != this.ratchetGroupSession.currentEpoch + 1) {
            throw SecureGroupSessionException(SecureGroupSessionException.NOT_CONSEQUENT_TICKET, "Ticket is not consequent")
        }

        val addInfo = RatchetGroupParticipantsInfo(addParticipants.size.toLong())
        val removeInfo = RatchetGroupParticipantsIds(removeParticipantIds.size.toLong())

        addParticipants.forEach { participant ->
            val participantId = participant.identifier
            val publicKeyData = this.crypto.exportPublicKey(participant.publicKey)
            addInfo.addParticipant(participantId, publicKeyData)
        }

        removeParticipantIds.forEach { id ->
            removeInfo.addId(id)
        }

        this.ratchetGroupSession.updateSessionState(ticket, addInfo, removeInfo)
    }

    /**
     * Serialize session.
     */
    fun serialize(): ByteArray {
        return this.ratchetGroupSession.serialize()
    }
}
