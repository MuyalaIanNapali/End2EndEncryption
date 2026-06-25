package org.e2ee.domain.usecase

import android.app.Activity
import org.e2ee.domain.model.BackupAuthResult
import org.e2ee.domain.repository.BackupAuthRepository

class EnableDriveBackupUseCase(
    private val repository: BackupAuthRepository
) {

    suspend operator fun invoke(
        activity: Activity
    ): BackupAuthResult {

        return repository.signInAndAuthorize(activity)
    }
}