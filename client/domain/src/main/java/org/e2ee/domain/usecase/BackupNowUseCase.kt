package org.e2ee.domain.usecase

import org.e2ee.domain.model.DomainResult
import org.e2ee.domain.repository.BackupAuthRepository
import javax.inject.Inject

class BackupNowUseCase @Inject constructor(
    private val backupAuthRepository: BackupAuthRepository
) {
    suspend operator fun invoke(activity: android.app.Activity): DomainResult<Boolean> {
        return backupAuthRepository.backupNow(activity)
    }
}