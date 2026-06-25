package org.e2ee.data.worker

import android.content.Context
import android.util.Log
import androidx.hilt.work.HiltWorker
import androidx.work.CoroutineWorker
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkManager
import androidx.work.WorkerParameters
import dagger.assisted.Assisted
import dagger.assisted.AssistedInject
import org.e2ee.data.repository.backup.BackupPreferencesRepository
import org.e2ee.data.repository.backup.BackupRepository
import org.e2ee.data.repository.backup.DriveTokenManager
import java.util.Calendar
import java.util.concurrent.TimeUnit

@HiltWorker
class BackupWorker @AssistedInject constructor(
    @Assisted context: Context,
    @Assisted workerParams: WorkerParameters,
    private val backupRepository: BackupRepository,
    private val backupPreferencesRepository: BackupPreferencesRepository,
    private val driveTokenManager: DriveTokenManager
) : CoroutineWorker(context, workerParams) {

    companion object {
        private const val TAG = "BackupWorker"
        const val WORK_NAME = "daily_backup_work"

        fun schedule(context: Context) {
            val now = Calendar.getInstance()
            val target = Calendar.getInstance().apply {
                set(Calendar.HOUR_OF_DAY, 6)
                set(Calendar.MINUTE, 0)
                set(Calendar.SECOND, 0)
                set(Calendar.MILLISECOND, 0)
                if (before(now)) add(Calendar.DAY_OF_MONTH, 1)
            }

            val initialDelayMs = target.timeInMillis - now.timeInMillis

            val workRequest = PeriodicWorkRequestBuilder<BackupWorker>(
                repeatInterval = 24,
                repeatIntervalTimeUnit = TimeUnit.HOURS
            )
                .setInitialDelay(initialDelayMs, TimeUnit.MILLISECONDS)
                .build()

            WorkManager.getInstance(context).enqueueUniquePeriodicWork(
                WORK_NAME,
                ExistingPeriodicWorkPolicy.UPDATE,
                workRequest
            )

            Log.i(TAG, "Backup worker scheduled. First run in ${initialDelayMs / 1000 / 60} minutes")
        }

        fun cancel(context: Context) {
            WorkManager.getInstance(context).cancelUniqueWork(WORK_NAME)
            Log.i(TAG, "Backup worker cancelled")
        }
    }

    override suspend fun doWork(): Result {
        Log.i(TAG, "BackupWorker started")

        if (!backupPreferencesRepository.isBackupEnabled()) {
            Log.i(TAG, "Backup is disabled, skipping")
            return Result.success()
        }

        // Use the Drive OAuth token, not the app JWT
        val driveAccessToken = driveTokenManager.get()
        if (driveAccessToken == null) {
            Log.w(TAG, "No Drive access token available — user needs to re-enable backup")
            // Disable backup so the UI reflects the broken state
            backupPreferencesRepository.setBackupEnabled(false)
            return Result.failure()
        }

        return try {
            backupRepository.backup(driveAccessToken)
            Log.i(TAG, "Backup completed successfully")
            Result.success()
        } catch (e: Exception) {
            Log.e(TAG, "Backup failed: ${e.message}", e)
            Result.retry()
        }
    }
}