package org.e2ee.domain.usecase

import org.e2ee.domain.model.DomainResult
import org.e2ee.domain.model.LoginRequest
import org.e2ee.domain.repository.AuthRepository
import javax.inject.Inject

class LoginUserUseCase @Inject constructor(
    private val authRepository: AuthRepository
) {
    suspend operator fun invoke(
        request: LoginRequest
    ): DomainResult<Boolean> {
        if (request.identifier.isBlank()) {
            return DomainResult.Error("Enter a valid username or email")
        }

        if (request.password.isBlank()) {
            return DomainResult.Error("Password cannot be empty")
        }

        return authRepository.login(request)
    }
}