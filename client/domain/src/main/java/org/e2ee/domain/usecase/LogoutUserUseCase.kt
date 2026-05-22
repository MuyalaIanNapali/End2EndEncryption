package org.e2ee.domain.usecase

import org.e2ee.domain.repository.AuthRepository
import javax.inject.Inject

class LogoutUserUseCase @Inject constructor(
    private val authRepository: AuthRepository
) {
    suspend operator fun invoke(){
        return authRepository.logout()
    }
}