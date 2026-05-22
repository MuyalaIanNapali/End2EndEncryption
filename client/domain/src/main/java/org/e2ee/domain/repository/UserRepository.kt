package org.e2ee.domain.repository

import org.e2ee.domain.model.DomainResult
import org.e2ee.domain.model.UpdateAccountInfoRequest

interface UserRepository {
    suspend fun updateAccountInfo(
       request : UpdateAccountInfoRequest
    ): DomainResult<Unit>

    suspend fun searchAllUsers(): DomainResult<List<String>>

    suspend fun searchByUsername(username: String): DomainResult<String>
}