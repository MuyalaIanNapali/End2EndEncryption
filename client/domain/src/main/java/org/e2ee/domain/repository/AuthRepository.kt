package org.e2ee.domain.repository

import org.e2ee.domain.model.DomainResult
import org.e2ee.domain.model.LoginRequest
import org.e2ee.domain.model.RegistrationRequest

interface AuthRepository {
        suspend fun register(request: RegistrationRequest): DomainResult<Boolean>

        suspend fun login(request: LoginRequest): Boolean

        suspend fun logout()
}