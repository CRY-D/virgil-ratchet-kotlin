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

import com.github.kittinunf.fuel.Fuel
import com.github.kittinunf.fuel.core.Method
import com.github.kittinunf.fuel.core.Response
import com.github.kittinunf.fuel.core.isSuccessful
import com.google.gson.Gson
import com.google.gson.reflect.TypeToken
import com.virgilsecurity.common.model.Completable
import com.virgilsecurity.common.model.Result
import com.virgilsecurity.ratchet.build.VirgilInfo
import com.virgilsecurity.ratchet.client.data.*
import com.virgilsecurity.ratchet.exception.ProtocolException
import com.virgilsecurity.ratchet.utils.OsUtils
import java.net.URL
import java.nio.charset.StandardCharsets
import java.util.logging.Logger

/**
 *  Client used to communicate with ratchet service.
 */
class RatchetClient : RatchetClientInterface {

    private val serviceUrl: String
    private val virgilAgentHeader: String
    private val tokenProvider: (() -> String)?
    private val gson = Gson()

    /**
     * Initializes a new `RatchetClient` instance.
     *
     * @param serviceUrl URL of service client will use.
     * @param tokenProvider Optional token provider for authentication.
     */
    @JvmOverloads
    constructor(serviceUrl: URL = URL(VIRGIL_API_BASE_URL),
                tokenProvider: (() -> String)? = null,
                product: String = VIRGIL_AGENT_PRODUCT,
                version: String = VirgilInfo.VERSION) {
        this.serviceUrl = serviceUrl.toString()
        this.tokenProvider = tokenProvider
        virgilAgentHeader =
                "$product;$VIRGIL_AGENT_FAMILY;${OsUtils.osAgentName};$version"
    }

    override fun uploadPublicKeys(
            longTermPublicKey: SignedPublicKey?,
            oneTimePublicKeys: List<ByteArray>
    ) = object : Completable {
        override fun execute() {
            val request = UploadPublicKeysRequest(null, longTermPublicKey, oneTimePublicKeys)
            executeRequest(PFS_BASE_URL, Method.PUT, request).get()
        }
    }

    override fun validatePublicKeys(
            longTermKeyId: ByteArray?,
            oneTimeKeysIds: List<ByteArray>
    ) = object : Result<ValidatePublicKeysResponse> {
        override fun get(): ValidatePublicKeysResponse {
            if (longTermKeyId == null && oneTimeKeysIds.isEmpty()) {
                return ValidatePublicKeysResponse(null, listOf())
            }

            val request = ValidatePublicKeysRequest(longTermKeyId, oneTimeKeysIds)
            val responseBody = executeRequest(PFS_BASE_URL + ACTIONS_VALIDATE, Method.POST, request).get()
            return gson.fromJson(responseBody, ValidatePublicKeysResponse::class.java)
        }
    }

    override fun getPublicKeySet(identity: String) = object : Result<PublicKeySet> {
        override fun get(): PublicKeySet {
            val request = GetPublicKeySetRequest(identity)
            val responseBody = executeRequest(PFS_BASE_URL + ACTIONS_PICK_ONE, Method.POST, request).get()

            return gson.fromJson(responseBody, PublicKeySet::class.java)
        }
    }

    override fun getMultiplePublicKeysSets(identities: List<String>) = object : Result<List<IdentityPublicKeySet>> {
        override fun get(): List<IdentityPublicKeySet> {
            val request = GetMultiplePublicKeysSetsRequest(identities)
            val responseBody = executeRequest(PFS_BASE_URL + ACTIONS_PICK_BATCH, Method.POST, request).get()

            val listType = object : TypeToken<List<IdentityPublicKeySet>>() {}.type
            return gson.fromJson<List<IdentityPublicKeySet>>(responseBody, listType)
        }
    }

    override fun deleteKeysEntity() = object : Completable {
        override fun execute() {
            executeRequest(PFS_BASE_URL, Method.DELETE, null).get()
        }
    }

    @Throws(ProtocolException)
    private fun validateResponse(response: Response) {
        if (!response.isSuccessful) {
            val errorBody = String(response.data, StandardCharsets.UTF_8)
            // Try to parse as generic error if needed, or just throw
            throw ProtocolException(response.statusCode, "Error response from server: $errorBody")
        }
    }

    @Throws(ProtocolException::class)
    private fun executeRequest(path: String, method: Method, body: Any?) = object : Result<String> {
        override fun get(): String {
            logger.fine("$method $path")
            val request = Fuel.request(method, "$serviceUrl$path")
                    .header(mapOf(VIRGIL_AGENT_HEADER_KEY to virgilAgentHeader))

            tokenProvider?.let {
                val token = it()
                request.header(mapOf(VIRGIL_AUTHORIZATION_HEADER_KEY to "Virgil $token"))
            }

            if (method == Method.POST || method == Method.PUT) {
                val jsonBody = gson.toJson(body)
                request.jsonBody(jsonBody)
            }
            val (_, response, result) = request.response()
            validateResponse(response)

            val responseBody = String(result.component1() ?: byteArrayOf(), StandardCharsets.UTF_8)
            logger.fine("result:\n$responseBody")

            return responseBody
        }
    }

    companion object {
        private const val VIRGIL_AGENT_HEADER_KEY = "virgil-agent"
        private const val VIRGIL_AGENT_PRODUCT = "ratchet"
        private const val VIRGIL_AGENT_FAMILY = "jvm"
        private const val VIRGIL_AUTHORIZATION_HEADER_KEY = "Authorization"

        private const val VIRGIL_API_BASE_URL = "https://api.virgilsecurity.com"
        private const val PFS_BASE_URL = "/pfs/v2/keys"
        private const val ACTIONS_VALIDATE = "/actions/validate"
        private const val ACTIONS_PICK_ONE = "/actions/pick-one"
        private const val ACTIONS_PICK_BATCH = "/actions/pick-batch"

        private val logger = Logger.getLogger(RatchetClient::class.java.name)
    }
}
