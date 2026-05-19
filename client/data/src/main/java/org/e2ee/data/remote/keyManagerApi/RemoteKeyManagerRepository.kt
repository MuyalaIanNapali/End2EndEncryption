package org.e2ee.data.remote.keyManagerApi

import org.e2ee.data.remote.keyManagerApi.dto.PreKeyBundle
import org.e2ee.data.remote.keyManagerApi.dto.UpdateOpkKeys
import org.e2ee.data.remote.keyManagerApi.dto.UpdateSignedPreKeyBundle

class RemoteKeyManagerRepository(
    private val api: KeyManagerApi
) {
    suspend fun updateSignedPreKey(request: UpdateSignedPreKeyBundle): Boolean {
        val response = api.updateSignedPreKey(request)
        if (response.isSuccessful) {
            return true
        } else {
            throw Exception("Failed to update signed pre-key: ${response.code()} ${response.message()}")
        }
    }

    suspend fun updateOneTimePreKeys(request: UpdateOpkKeys): Boolean {
        val response = api.updateOneTimePreKeys(request)
        if (response.isSuccessful) {
            return true
        } else {
            throw Exception("Failed to update one-time pre-keys: ${response.code()} ${response.message()}")
        }
    }

    suspend fun updatePreKeyBundle(request: PreKeyBundle): Boolean {
        val response = api.updatePreKeyBundle(request)
        if (response.isSuccessful) {
            return true
        } else {
            throw Exception("Failed to update pre-key bundle: ${response.code()} ${response.message()}")
        }
    }
}