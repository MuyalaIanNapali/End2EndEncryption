package org.e2ee.domain.repository

import android.app.Activity
import org.e2ee.domain.model.BackupAuthResult

interface BackupAuthRepository {

    suspend fun signInAndAuthorize(
        activity: Activity
    ): BackupAuthResult
}