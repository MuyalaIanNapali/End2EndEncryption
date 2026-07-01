package org.e2ee.domain.repository

import android.app.Activity
import org.e2ee.domain.model.BackupAuthResult
import org.e2ee.domain.model.DomainResult

interface BackupAuthRepository {

    suspend fun signInAndAuthorize(
        activity: Activity
    ): BackupAuthResult

    suspend fun backupNow(
        activity: Activity
    ): DomainResult<Boolean>

    suspend fun restoreBackup(
        activity: Activity
    ): DomainResult<Boolean>
}