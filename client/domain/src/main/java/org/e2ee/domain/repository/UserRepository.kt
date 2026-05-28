package org.e2ee.domain.repository

import org.e2ee.domain.model.DomainResult
import org.e2ee.domain.model.RemoteUserDetails
import org.e2ee.domain.model.UpdateAccountInfoRequest

interface UserRepository {
    suspend fun updateAccountInfo(
       request : UpdateAccountInfoRequest
    ): DomainResult<Unit>

    suspend fun searchAllUsers(): DomainResult<List<RemoteUserDetails>>

    suspend fun searchByUsername(username: String): DomainResult<RemoteUserDetails>

    suspend fun searchUsersByUsername(username: String): DomainResult<List<RemoteUserDetails>>

    suspend fun addContact(details: RemoteUserDetails)
}