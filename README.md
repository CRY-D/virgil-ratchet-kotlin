# Virgil Security Ratchet Java/Kotlin SDK

[![Build Status](https://travis-ci.com/VirgilSecurity/virgil-ratchet-kotlin.svg?branch=master)](https://travis-ci.com/VirgilSecurity/virgil-ratchet-kotlin)
[![Maven Central](https://maven-badges.herokuapp.com/maven-central/com.virgilsecurity/ratchet/badge.svg)](https://maven-badges.herokuapp.com/maven-central/com.virgilsecurity/ratchet)
[![GitHub license](https://img.shields.io/badge/license-BSD%203--Clause-blue.svg)](https://github.com/VirgilSecurity/virgil/blob/master/LICENSE)

[Introduction](#introduction) | [SDK Features](#sdk-features) | [Installation](#installation) | [Peer-to-peer Chat Example](#peer-to-peer-chat-example) | [Group Chat Example](#group-chat-example) | [Support](#support)

## Introduction

<a href="https://developer.virgilsecurity.com/docs"><img width="230px" src="https://cdn.virgilsecurity.com/assets/images/github/logos/virgil-logo-red.png" align="left" hspace="10" vspace="6"></a>
[Virgil Security](https://virgilsecurity.com) provides a set of open source libraries for adding security to any application. If you're developing a chat application, you'll understand the need for a high level of data protection to ensure confidentiality and data integrity.

This SDK is an implementation of the [Double Ratchet Algorithm](https://signal.org/docs/specifications/doubleratchet/). With the powerful tools in this SDK, you can protect encrypted data, even if user messages or a private key has been stolen. The Double Ratchet SDK not only assigns a private encryption key with each chat session, but also allows the developer to limit the lifecycle of these keys. In the event an active key is stolen, it will expire according to the predetermined lifecycle you had set in your application.

This version of the SDK is independent of Virgil Cloud and Virgil Cards. You can use your own signaling server or P2P transport (like WebRTC) to exchange public keys.

# SDK Features
- manage users' one-time keys (OTK) and long-term keys (LTK)
- enable group or peer-to-peer chat encryption
- uses the [Virgil crypto library](https://github.com/VirgilSecurity/virgil-crypto-c)

## Installation

You can easily add Ratchet SDK dependency to your project with:

### Maven

```
<dependencies>
    <dependency>
        <groupId>com.virgilsecurity</groupId>
        <artifactId>ratchet</artifactId>
        <version><latest-version></version>
    </dependency>
</dependencies>
```

### Gradle

Add `jcenter()` repository if missing, then update gradle dependencies:

```
    implementation "com.virgilsecurity:ratchet:<latest-version>"
```

### Initialize SDK

To begin, each user must run the initialization.

```kotlin
val identity = "Alice"
val identityKeyPair = virgilCrypto.generateKeyPair(KeyPairType.ED25519)

val context = SecureChatContext(identity = identity,
                                identityKeyPair = identityKeyPair)

val secureChat = SecureChat(context = context)
```

### Key Rotation

During the initialization process and periodically, you should rotate keys. The `rotateKeys` method generates special keys that have their own life-time:

* **One-time Key (OTK)** - each time chat participants want to create a session, a single one-time key is obtained and discarded.
* **Long-term Key (LTK)** - rotated periodically and is signed with the Identity Private Key.

```kotlin
val rotationResult = secureChat.rotateKeys().get()

// You should now upload rotationResult.longTermPublicKey and rotationResult.oneTimePublicKeys
// to your signaling server or send them to your peer.
mySignalingServer.uploadKeys(identity, rotationResult.longTermPublicKey, rotationResult.oneTimePublicKeys)
```

## Peer-to-peer Chat Example

### Send initial encrypted message
Let's assume Alice wants to start communicating with Bob:
- first, Alice has to obtain Bob's public keys from your signaling server
- then, Alice creates a new chat session
- Alice encrypts the initial message
- finally, Alice stores the generated session locally.

```kotlin
// 1. Get Bob's keys from your server
val bobsKeys = mySignalingServer.getKeys("Bob")

// 2. Start new secure session with Bob
val bobPublicKeySet = PublicKeySet(bobsKeys.identityPublicKey, bobsKeys.longTermPublicKey, bobsKeys.oneTimePublicKey)
val session = secureChat.startNewSessionAsSender(receiverIdentity = "Bob",
                                                 receiverIdentityPublicKey = bobsKeys.identityPublicKey,
                                                 publicKeySet = bobPublicKeySet)

// 3. Encrypt message
val ratchetMessage = session.encrypt("Hello, Bob!")

// 4. Store session
secureChat.storeSession(session)

// 5. Send ratchetMessage.serialize() to Bob
```

### Decrypt the initial message

Bob receives the message and:
- starts the chat session as a receiver
- decrypts the message

```kotlin
val ratchetMessage = RatchetMessage.deserialize(receivedData)

val secureSession = secureChat.startNewSessionAsReceiver(senderIdentity = "Alice",
                                                         senderIdentityPublicKey = alicesIdentityPublicKey,
                                                         ratchetMessage = ratchetMessage)

val decryptedMessage = secureSession.decryptString(ratchetMessage)

secureChat.storeSession(secureSession)
```

## Group Chat Example

### Create Group Chat
Alice wants to start a group chat with Bob and Carol.

```kotlin
val sessionId = virgilCrypto.generateRandomData(32)
val ticket = secureChat.startNewGroupSession(sessionId)

// Alice's own identifier in the group
val aliceId = virgilCrypto.generateRandomData(32)

val participants = listOf(
    RatchetParticipant("Bob", bobsPublicKey, bobsId),
    RatchetParticipant("Carol", carolsPublicKey, carolsId)
)

val groupSession = secureChat.startGroupSession(participants, sessionId, ticket, aliceId)
secureChat.storeGroupSession(groupSession)
```

### Send the Group Ticket
Alice provides the group chat ticket to other members via their peer-to-peer sessions.

```kotlin
val ticketData = ticket.serialize()

participants.forEach { participant ->
    val session = secureChat.existingSession(participant.identity)
    val encryptedTicket = session.encrypt(ticketData).serialize()
    // Send encryptedTicket to participant
}
```

### Join the Group Chat
Bob receives the ticket and joins:

```kotlin
val ticket = RatchetGroupMessage.deserialize(decryptedTicketData)
val participants = listOf(
    RatchetParticipant("Alice", alicesPublicKey, alicesId),
    RatchetParticipant("Carol", carolsPublicKey, carolsId)
)

val groupSession = secureChat.startGroupSession(participants, sessionId, ticket, bobsId)
secureChat.storeGroupSession(groupSession)
```

## License

This library is released under the [3-clause BSD License](LICENSE).

## Support
Our developer support team is here to help you. Find out more information at our [Help Center](https://help.virgilsecurity.com/).
