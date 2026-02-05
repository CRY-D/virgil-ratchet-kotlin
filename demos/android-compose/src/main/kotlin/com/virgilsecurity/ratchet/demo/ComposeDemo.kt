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

// Conceptual Android Compose Demo
// This file demonstrates how to integrate the decoupled SDK into a Compose-based Android App.

/*
import androidx.compose.runtime.*
import androidx.compose.foundation.layout.*
import androidx.compose.material.*
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.launch
*/

import com.virgilsecurity.ratchet.securechat.SecureChat
import com.virgilsecurity.ratchet.securechat.SecureChatContext
import com.virgilsecurity.sdk.crypto.VirgilCrypto
import com.virgilsecurity.sdk.crypto.VirgilKeyPair
import com.virgilsecurity.sdk.crypto.KeyPairType
import java.util.UUID

/**
 * A conceptual ViewModel that manages secure chat state in an Android App.
 */
class SecureChatViewModel(
    val identity: String,
    val crypto: VirgilCrypto,
    val keyPair: VirgilKeyPair,
    val storagePath: String
) {
    // The decoupled SecureChat instance
    private val secureChat: SecureChat by lazy {
        val context = SecureChatContext(
            identity = identity,
            identityKeyPair = keyPair,
            rootPath = storagePath,
            virgilCrypto = crypto,
            ratchetClient = null // Using our own signaling server
        )
        SecureChat(context)
    }

    // Example of rotating keys and getting them for your backend
    fun rotateAndPublishKeys() {
        val rotationResult = secureChat.rotateKeys().get()

        // Simulating upload to your own signaling server
        val ltk = rotationResult.longTermPublicKey
        val otks = rotationResult.oneTimePublicKeys

        println("Publishing ${otks.size} OTKs to signaling server...")
        // mySignalingServer.upload(identity, ltk, otks)
    }

    fun sendMessage(recipientIdentity: String, recipientPublicKey: Any, message: String) {
        // Logic to start session if not exists, encrypt, and send via your signaling mechanism
        // ...
    }
}

/*
@Composable
fun ChatScreen(viewModel: SecureChatViewModel) {
    var messageText by remember { mutableStateOf("") }
    val messages = remember { mutableStateListOf<String>() }

    Column(modifier = Modifier.fillMaxSize().padding(16.dp)) {
        Text("Secure Chat Identity: ${viewModel.identity}", style = MaterialTheme.typography.h6)

        Spacer(modifier = Modifier.height(16.dp))

        Button(onClick = { viewModel.rotateAndPublishKeys() }) {
            Text("Rotate & Publish Keys")
        }

        Spacer(modifier = Modifier.height(16.dp))

        // Message List
        Box(modifier = Modifier.weight(1f)) {
            // ... Display messages ...
        }

        Row {
            TextField(
                value = messageText,
                onValueChange = { messageText = it },
                modifier = Modifier.weight(1f)
            )
            Button(onClick = {
                // viewModel.sendMessage(...)
                messageText = ""
            }) {
                Text("Send")
            }
        }
    }
}
*/
