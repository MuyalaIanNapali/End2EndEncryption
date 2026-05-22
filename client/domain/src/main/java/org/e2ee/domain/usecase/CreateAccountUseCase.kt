package org.e2ee.domain.usecase

import org.e2ee.domain.model.DomainResult
import org.e2ee.domain.model.RegistrationRequest
import org.e2ee.domain.repository.AuthRepository
import javax.inject.Inject

class CreateAccountUseCase @Inject constructor (
    private val authRepository: AuthRepository
) {
    suspend operator fun invoke(
        request: RegistrationRequest
    ): DomainResult<Boolean> {
        if (request.username.isBlank()) {
            return DomainResult.Error("Username cannot be empty")
        }

        if (request.email.isBlank()) {
            return DomainResult.Error("Email cannot be empty")
        }

        if (request.password.length < 8) {
            return DomainResult.Error("Password must be at least 8 characters")
        }

        return authRepository.register(request)
    }
}