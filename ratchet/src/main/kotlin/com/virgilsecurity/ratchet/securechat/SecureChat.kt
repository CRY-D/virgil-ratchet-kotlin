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

import com.virgilsecurity.common.model.Completable
import com.virgilsecurity.crypto.ratchet.*
import com.virgilsecurity.ratchet.client.RatchetClientInterface
import com.virgilsecurity.ratchet.client.data.PublicKeySet
import com.virgilsecurity.ratchet.exception.SecureChatException
import com.virgilsecurity.ratchet.keystorage.*
import com.virgilsecurity.common.model.Result
import com.virgilsecurity.ratchet.client.data.SignedPublicKey
import com.virgilsecurity.ratchet.securechat.keysrotation.KeyRotationResult
import com.virgilsecurity.ratchet.securechat.keysrotation.KeysRotator
import com.virgilsecurity.ratchet.securechat.keysrotation.KeysRotatorInterface
import com.virgilsecurity.ratchet.sessionstorage.FileGroupSessionStorage
import com.virgilsecurity.ratchet.sessionstorage.FileSessionStorage
import com.virgilsecurity.ratchet.sessionstorage.GroupSessionStorage
import com.virgilsecurity.ratchet.sessionstorage.SessionStorage
import com.virgilsecurity.ratchet.utils.hexEncodedString
import com.virgilsecurity.sdk.crypto.KeyPairType
import com.virgilsecurity.sdk.crypto.VirgilCrypto
import com.virgilsecurity.sdk.crypto.VirgilPrivateKey
import com.virgilsecurity.sdk.crypto.VirgilPublicKey
import java.util.logging.Logger

class SecureChat {

    val identity: String
    val identityPrivateKey: VirgilPrivateKey
    val crypto: VirgilCrypto
    val longTermKeysStorage: LongTermKeysStorage
    val oneTimeKeysStorage: OneTimeKeysStorage
    val sessionStorage: SessionStorage
    val groupSessionStorage: GroupSessionStorage
    val client: RatchetClientInterface?
    val keyId = RatchetKeyId()
    val keysRotator: KeysRotatorInterface

    /**
     * Create new instance.
     *
     * @param context Contains info required to instantiate [SecureChat] object.
     */
    constructor(context: SecureChatContext) {
        this.crypto = context.virgilCrypto
        this.client = context.ratchetClient
        this.identityPrivateKey = context.identityKeyPair.privateKey
        this.identity = context.identity

        this.longTermKeysStorage =
                FileLongTermKeysStorage(this.identity, this.crypto, context.identityKeyPair, context.rootPath)
        this.oneTimeKeysStorage =
                FileOneTimeKeysStorage(this.identity, this.crypto, context.identityKeyPair, context.rootPath)
        this.sessionStorage =
                FileSessionStorage(this.identity, crypto, context.identityKeyPair, context.rootPath)
        this.groupSessionStorage =
                FileGroupSessionStorage(this.identity, crypto, context.identityKeyPair, context.rootPath)
        this.keysRotator = KeysRotator(
                crypto, context.identityKeyPair.privateKey,
                context.orphanedOneTimeKeyTtl, context.longTermKeyTtl, context.outdatedLongTermKeyTtl,
                context.desiredNumberOfOneTimeKeys, this.longTermKeysStorage, this.oneTimeKeysStorage,
                this.client
        )
    }

    /**
     * Create new instance.
     *
     * @param crypto VirgilCrypto instance.
     * @param identityPrivateKey Identity private key.
     * @param identity Identity.
     * @param client Ratchet client.
     * @param longTermKeysStorage Long-term keys storage.
     * @param oneTimeKeysStorage One-time keys storage.
     * @param sessionStorage Session storage.
     * @param groupSessionStorage Group session storage.
     * @param keysRotator Keys rotation
     */
    constructor(
            crypto: VirgilCrypto,
            identityPrivateKey: VirgilPrivateKey,
            identity: String,
            client: RatchetClientInterface?,
            longTermKeysStorage: LongTermKeysStorage,
            oneTimeKeysStorage: OneTimeKeysStorage,
            sessionStorage: SessionStorage,
            groupSessionStorage: GroupSessionStorage,
            keysRotator: KeysRotatorInterface
    ) {
        this.crypto = crypto
        this.identityPrivateKey = identityPrivateKey
        this.identity = identity
        this.client = client
        this.longTermKeysStorage = longTermKeysStorage
        this.oneTimeKeysStorage = oneTimeKeysStorage
        this.sessionStorage = sessionStorage
        this.groupSessionStorage = groupSessionStorage
        this.keysRotator = keysRotator
    }

    /**
     * Rotates keys.
     *
     * Rotation process:
     * - Retrieve all one-time keys
     * - Delete one-time keys that were marked as orphaned more than orphanedOneTimeKeyTtl seconds ago
     * - Retrieve all long-term keys
     * - Delete long-term keys that were marked as outdated more than outdatedLongTermKeyTtl seconds ago
     * - Check that all relevant long-term and one-time keys are in the cloud (if client is provided)
     * - Mark used one-time keys as used
     * - Decide on long-term key rotation
     * - Generate needed number of one-time keys
     *
     * @return KeyRotationResult.
     */
    fun rotateKeys() = object : Result<KeyRotationResult> {
        override fun get(): KeyRotationResult {
            logger.fine("Started keys rotation")

            return this@SecureChat.keysRotator.rotateKeys().get()
        }
    }

    /**
     * Stores session.
     * NOTE: This method is used for storing new session as well as updating existing ones after operations that
     * change session's state (encrypt and decrypt), therefore is session already exists in storage, it will
     * be overwritten.
     *
     * @param session Session to store.
     */
    fun storeSession(session: SecureSession) {
        logger.fine("Storing session with ${session.participantIdentity} name: ${session.name}")

        this.sessionStorage.storeSession(session)
    }

    /**
     * Stores group session.
     *
     * NOTE: This method is used for storing new session as well as updating existing ones after operations that
     * change session's state (encrypt, decrypt, setParticipants, updateParticipants), therefore is session already
     * exists in storage, it will be overwritten.
     *
     * @param session GroupSession to store.
     */
    fun storeGroupSession(session: SecureGroupSession) {
        logger.fine("Storing group session with id ${session.identifier().hexEncodedString()}")

        this.groupSessionStorage.storeSession(session)
    }

    /**
     * Checks for existing session with given participant in the storage.
     *
     * @param participantIdentity Participant identity.
     * @param name Session name.
     *
     * @return SecureSession if exists.
     */
    fun existingSession(participantIdentity: String, name: String? = null): SecureSession? {
        val session = this.sessionStorage.retrieveSession(participantIdentity, name ?: OPERATION_DEFAULT_SESSION_NAME)
        return if (session != null) {
            logger.fine("Found existing session with $participantIdentity")
            session
        } else {
            logger.fine("Existing session with $participantIdentity was not found")
            null
        }
    }

    /**
     * Deletes session with given participant identity.
     *
     * @param participantIdentity Participant identity.
     * @param name Session name.
     */
    fun deleteSession(participantIdentity: String, name: String? = null) {
        logger.fine("Deleting session with $participantIdentity")

        this.sessionStorage.deleteSession(participantIdentity, name ?: OPERATION_DEFAULT_SESSION_NAME)
    }

    /**
     * Deletes sessions with given participant identity.
     *
     * @param participantIdentity Participant identity.
     */
    fun deleteAllSessions(participantIdentity: String) {
        logger.fine("Deleting session with $participantIdentity")

        this.sessionStorage.deleteSession(participantIdentity, null)
    }

    /**
     * Deletes group session with given identifier.
     *
     * @param sessionId Session identifier.
     */
    fun deleteGroupSession(sessionId: ByteArray) {
        logger.fine("Deleting group session with ${sessionId.hexEncodedString()}")
        this.groupSessionStorage.deleteSession(sessionId)
    }

    /**
     * Starts new session with given participant using his identity and public key.
     * This method will use the [RatchetClientInterface] to fetch the public key set.
     *
     * NOTE: This operation doesn't store session to storage automatically. Use storeSession().
     *
     * @param receiverIdentity Receiver identity.
     * @param receiverIdentityPublicKey Receiver identity public key.
     * @param name Session name.
     */
    fun startNewSessionAsSender(receiverIdentity: String,
                                receiverIdentityPublicKey: VirgilPublicKey,
                                name: String? = null) = object : Result<SecureSession> {
        override fun get(): SecureSession {
            logger.fine("Starting new session with $receiverIdentity")

            if (this@SecureChat.client == null) {
                throw SecureChatException(SecureChatException.CLIENT_NOT_PROVIDED, "RatchetClient should be provided to fetch public keys")
            }

            if (existingSession(receiverIdentity, name ?: OPERATION_DEFAULT_SESSION_NAME) != null) {
                throw SecureChatException(SecureChatException.SESSION_ALREADY_EXISTS, "Session is already exists")
            }

            if (receiverIdentityPublicKey.keyPairType != KeyPairType.ED25519) {
                throw SecureChatException(SecureChatException.INVALID_KEY_TYPE, "Key type should be ED25519")
            }

            val publicKeySet = this@SecureChat.client.getPublicKeySet(receiverIdentity).get()

            return startNewSessionAsSender(
                    receiverIdentity, receiverIdentityPublicKey, name,
                    publicKeySet.identityPublicKey, publicKeySet.longTermPublicKey, publicKeySet.oneTimePublicKey
            )
        }
    }

    /**
     * Starts new session with given participant using his identity and public key set.
     *
     * NOTE: This operation doesn't store session to storage automatically. Use storeSession().
     *
     * @param receiverIdentity Receiver identity.
     * @param receiverIdentityPublicKey Receiver identity public key.
     * @param publicKeySet Receiver public key set.
     * @param name Session name.
     */
    fun startNewSessionAsSender(receiverIdentity: String,
                                receiverIdentityPublicKey: VirgilPublicKey,
                                publicKeySet: PublicKeySet,
                                name: String? = null): SecureSession {
        logger.fine("Starting new session with $receiverIdentity")

        if (existingSession(receiverIdentity, name ?: OPERATION_DEFAULT_SESSION_NAME) != null) {
            throw SecureChatException(SecureChatException.SESSION_ALREADY_EXISTS, "Session is already exists")
        }

        if (receiverIdentityPublicKey.keyPairType != KeyPairType.ED25519) {
            throw SecureChatException(SecureChatException.INVALID_KEY_TYPE, "Key type should be ED25519")
        }

        return startNewSessionAsSender(
                receiverIdentity, receiverIdentityPublicKey, name,
                publicKeySet.identityPublicKey, publicKeySet.longTermPublicKey, publicKeySet.oneTimePublicKey
        )
    }

    private fun startNewSessionAsSender(
            identity: String, identityPublicKey: VirgilPublicKey, name: String?,
            identityPublicKeyData: ByteArray, longTermPublicKey: SignedPublicKey, oneTimePublicKey: ByteArray?
    ): SecureSession {
        if (!this.keyId.computePublicKeyId(identityPublicKeyData)!!.contentEquals(this.keyId.computePublicKeyId(this.crypto.exportPublicKey(identityPublicKey)))) {
            throw SecureChatException(SecureChatException.IDENTITY_KEY_DOESNT_MATCH)
        }
        if (!this.crypto.verifySignature(longTermPublicKey.signature, longTermPublicKey.publicKey, identityPublicKey)) {
            throw SecureChatException(SecureChatException.INVALID_LONG_TERM_KEY_SIGNATURE)
        }
        if (oneTimePublicKey == null) {
            logger.warning("Creating weak session with $identity")
        }
        val privateKeyData = this.crypto.exportPrivateKey(this.identityPrivateKey)
        return SecureSession(
                crypto, identity, name ?: OPERATION_DEFAULT_SESSION_NAME,
                privateKeyData, identityPublicKeyData, longTermPublicKey.publicKey, oneTimePublicKey
        )
    }

    /**
     * Starts multiple new sessions with given participants using their identity cards.
     *
     * NOTE: This operation doesn't store sessions to storage automatically. Use storeSession().
     *
     * @param receiverIdentities Receivers identities.
     * @param receiverPublicKeys Receivers public keys.
     * @param name Session name.
     */
    fun startMutipleNewSessionsAsSender(receiverIdentities: List<String>,
                                        receiverPublicKeys: List<VirgilPublicKey>,
                                        name: String? = null) = object : Result<List<SecureSession>> {
        override fun get(): List<SecureSession> {
            logger.fine("Starting new sessions with $receiverIdentities")

            if (this@SecureChat.client == null) {
                throw SecureChatException(SecureChatException.CLIENT_NOT_PROVIDED, "RatchetClient should be provided to fetch public keys")
            }

            if (receiverIdentities.size != receiverPublicKeys.size) {
                throw IllegalArgumentException("Identities and public keys counts should match")
            }

            receiverIdentities.forEach {
                if (existingSession(it, name ?: OPERATION_DEFAULT_SESSION_NAME) != null) {
                    throw SecureChatException(
                            SecureChatException.SESSION_ALREADY_EXISTS,
                            "Session with $it already exists"
                    )
                }
            }

            receiverPublicKeys.forEach {
                if (it.keyPairType != KeyPairType.ED25519) {
                    throw SecureChatException(SecureChatException.INVALID_KEY_TYPE,
                                              "Public key should be ED25519 type")
                }
            }

            val publicKeysSets = this@SecureChat.client.getMultiplePublicKeysSets(receiverIdentities).get()
            if (publicKeysSets.size != receiverIdentities.size) {
                throw SecureChatException(SecureChatException.PUBLIC_KEY_SETS_MISMATCH, "Wrong public keys count")
            }
            val sessions = mutableListOf<SecureSession>()
            for (i in receiverIdentities.indices) {
                val identity = receiverIdentities[i]
                val publicKey = receiverPublicKeys[i]

                val publicKeySet = publicKeysSets.firstOrNull { it.identity == identity }
                        ?: throw SecureChatException(
                                SecureChatException.PUBLIC_KEY_SETS_MISMATCH,
                                "Wrong public keys count"
                        )

                val session = startNewSessionAsSender(
                        identity,
                        publicKey,
                        name,
                        publicKeySet.identityPublicKey,
                        publicKeySet.longTermPublicKey,
                        publicKeySet.oneTimePublicKey)

                sessions.add(session)
            }
            return sessions
        }
    }

    private fun replaceOneTimeKey() = object : Completable {
        override fun execute() {
            logger.fine("Adding one time key")
            val oneTimePublicKey: ByteArray

            try {
                this@SecureChat.oneTimeKeysStorage.startInteraction()

                try {
                    val keyPair = this@SecureChat.crypto.generateKeyPair(KeyPairType.CURVE25519)
                    val oneTimePrivateKey = this@SecureChat.crypto.exportPrivateKey(keyPair.privateKey)
                    oneTimePublicKey = this@SecureChat.crypto.exportPublicKey(keyPair.publicKey)
                    val keyId = this@SecureChat.keyId.computePublicKeyId(oneTimePublicKey)

                    this@SecureChat.oneTimeKeysStorage.storeKey(oneTimePrivateKey, keyId)

                    logger.fine("Saved one-time key successfully")
                } catch (e: Exception) {
                    logger.severe("Error saving one-time key")
                    return
                }

                if (this@SecureChat.client != null) {
                    try {
                        this@SecureChat.client.uploadPublicKeys(
                                null, mutableListOf(oneTimePublicKey)
                        ).execute()

                        logger.fine("Added one-time key successfully")
                    } catch (e: Exception) {
                        logger.severe("Error adding one-time key")
                    }
                } else {
                    logger.warning("Client is not provided, one-time key was only saved locally. " +
                                           "Make sure to upload it to your server.")
                }
            } finally {
                this@SecureChat.oneTimeKeysStorage.stopInteraction()
            }
        }
    }

    /**
     * Responds with new session with given participant using his initiation message.
     *
     * NOTE: This operation doesn't store session to storage automatically. Use storeSession().
     *
     * @param senderIdentity Sender identity.
     * @param senderIdentityPublicKey Sender identity public key.
     * @param ratchetMessage Ratchet initiation message (should be PREKEY message).
     * @param name Session name.
     *
     * @return SecureSession.
     */
    fun startNewSessionAsReceiver(senderIdentity: String,
                                  senderIdentityPublicKey: VirgilPublicKey,
                                  ratchetMessage: RatchetMessage,
                                  name: String? = null): SecureSession {
        logger.fine("Responding to session with $senderIdentity")

        if (existingSession(senderIdentity, name) != null) {
            throw SecureChatException(
                    SecureChatException.SESSION_ALREADY_EXISTS,
                    "Session already exists"
            )
        }

        if (senderIdentityPublicKey.keyPairType != KeyPairType.ED25519) {
            throw SecureChatException(
                    SecureChatException.INVALID_KEY_TYPE,
                    "Identity public key should be a ED25519 type"
            )
        }

        if (ratchetMessage.type != MsgType.PREKEY) {
            throw SecureChatException(
                    SecureChatException.INVALID_MESSAGE_TYPE,
                    "Ratchet message should be PREKEY type"
            )
        }

        val receiverLongTermPublicKey = ratchetMessage.longTermPublicKey
        val longTermKeyId = this.keyId.computePublicKeyId(receiverLongTermPublicKey)
        val receiverLongTermPrivateKey = this.longTermKeysStorage.retrieveKey(longTermKeyId)
        val receiverOneTimePublicKey = ratchetMessage.oneTimePublicKey

        val receiverOneTimeKeyId = if (receiverOneTimePublicKey.isEmpty()) {
            null
        } else {
            this.keyId.computePublicKeyId(receiverOneTimePublicKey)
        }
        val receiverOneTimePrivateKey: OneTimeKey?
        var interactionStarted = false
        try {
            if (receiverOneTimeKeyId == null) {
                receiverOneTimePrivateKey = null
            } else {
                this.oneTimeKeysStorage.startInteraction()
                interactionStarted = true
                receiverOneTimePrivateKey = this.oneTimeKeysStorage.retrieveKey(receiverOneTimeKeyId)
            }

            val session = SecureSession(
                    this.crypto,
                    senderIdentity,
                    name ?: OPERATION_DEFAULT_SESSION_NAME,
                    this.identityPrivateKey,
                    receiverLongTermPrivateKey,
                    receiverOneTimePrivateKey,
                    this.crypto.exportPublicKey(senderIdentityPublicKey),
                    ratchetMessage
            )

            if (receiverOneTimeKeyId != null) {
                this.oneTimeKeysStorage.deleteKey(receiverOneTimeKeyId)
                replaceOneTimeKey().execute()
            }
            return session
        } finally {
            if (interactionStarted) {
                this.oneTimeKeysStorage.stopInteraction()
            }
        }
    }

    /**
     * Creates RatchetGroupMessage that starts new group chat.
     *
     * NOTE: Other participants should receive this message using encrypted channel (SecureSession).
     *
     * @param sessionId Session Id. Should be 32 byte.
     *
     * @return RatchetGroupMessage that should be then passed to startGroupSession().
     */
    fun startNewGroupSession(sessionId: ByteArray): RatchetGroupMessage {
        val ticket = RatchetGroupTicket()
        ticket.setRng(this.crypto.rng)

        if (sessionId.size != RatchetCommon().sessionIdLen) {
            throw SecureChatException(SecureChatException.INVALID_SESSION_ID_LENGTH, "Session ID should be 32 byte length")
        }
        ticket.setupTicketAsNew(sessionId)

        return ticket.ticketMessage
    }

    /**
     * Creates secure group session that was initiated by someone.
     *
     * NOTE: This operation doesn't store session to storage automatically. Use storeSession().
     * RatchetGroupMessage should be of GROUP_INFO type. Such messages should be sent encrypted (using SecureSession).
     *
     * @param participants Participant info.
     * @param sessionId Session Id. Should be 32 byte.
     * @param ratchetMessage Ratchet group message of GROUP_INFO type.
     * @param myIdentifier My identifier in this group.
     *
     * @return SecureGroupSession.
     */
    fun startGroupSession(participants: List<RatchetParticipant>,
                          sessionId: ByteArray,
                          ratchetMessage: RatchetGroupMessage,
                          myIdentifier: ByteArray): SecureGroupSession {
        if (ratchetMessage.type != GroupMsgType.GROUP_INFO) {
            throw SecureChatException(
                    SecureChatException.INVALID_MESSAGE_TYPE,
                    "Ratchet message should be GROUP_INFO type"
            )
        }

        if (ratchetMessage.sessionId == null) throw IllegalArgumentException("sessionId should not be null")

        if (!ratchetMessage.sessionId.contentEquals(sessionId)) {
            throw SecureChatException(SecureChatException.SESSION_ID_MISMATCH)
        }

        val privateKeyData = this.crypto.exportPrivateKey(this.identityPrivateKey)

        return SecureGroupSession(this.crypto, privateKeyData, myIdentifier,
                ratchetMessage,
                participants)
    }

    /**
     * Returns existing group session.
     *
     * @param sessionId Session identifier.
     *
     * @return Stored session if found, null otherwise.
     */
    fun existingGroupSession(sessionId: ByteArray): SecureGroupSession? {
        val identifier = sessionId.hexEncodedString()
        val session = this.groupSessionStorage.retrieveSession(sessionId)
        if (session == null) {
            logger.fine("Existing session with identifier: $identifier was not found")
        } else {
            logger.fine("Found existing group session with identifier: $identifier")
        }

        return session
    }

    /**
     * Removes all data corresponding to this user: sessions and keys.
     */
    fun reset() = object : Completable {
        override fun execute() {
            logger.fine("Reset secure chat")

            if (this@SecureChat.client != null) {
                logger.fine("Resetting cloud")
                this@SecureChat.client.deleteKeysEntity().execute()
            }

            logger.fine("Resetting one-time keys")
            this@SecureChat.oneTimeKeysStorage.reset()

            logger.fine("Resetting long-term keys")
            this@SecureChat.longTermKeysStorage.reset()

            logger.fine("Resetting sessions")
            this@SecureChat.sessionStorage.reset()

            logger.fine("Resetting success")
        }
    }

    companion object {
        /**
         * Default session name.
         */
        private const val OPERATION_DEFAULT_SESSION_NAME = "DEFAULT"

        private val logger = Logger.getLogger(SecureChat::class.java.name)
    }
}
