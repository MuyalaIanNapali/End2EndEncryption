package org.e2ee.data.repository.backup

import android.util.Log
import org.e2ee.crypto.backup.BackupDB
import org.e2ee.common.Share
import org.e2ee.data.local.database.serializeBackup
import org.e2ee.data.local.user.share.RecoveryShareStore
import org.e2ee.data.remote.shares.RemoteShareRepository
import org.e2ee.data.remote.shares.dto.ShareDto
import org.e2ee.data.remote.shares.dto.UpdateSharesRequest
import org.e2ee.data.remote.shares.dto.toShareDto
import javax.inject.Inject

class BackupRepository @Inject constructor(
    private val backupExporter: BackupExporter,
    private val driveRepository: GoogleDriveRepository,
    private val recoveryShareStore: RecoveryShareStore,
    private val remoteShareRepository: RemoteShareRepository
) {
    suspend fun createEncryptedBackup(): Pair<ByteArray, List<Share>> {

        val payload = backupExporter.export()

        val jsonBytes = serializeBackup(payload)

        return BackupDB().encryptDatabaseBackup(
            jsonBytes
        )
    }

    suspend fun uploadShareToBackend(share: ShareDto) {
        remoteShareRepository.updateUserShare(UpdateSharesRequest(share = share))
    }

    suspend fun backup(
        googleAccessToken: String
    ) {
        try {

            Log.i("BackupRepository", "Starting backup process")
            val (encryptedBackup, shares) =
                createEncryptedBackup()

            Log.i("BackupRepository", "Encrypted backup created, size: ${encryptedBackup.size}, shares count: ${shares.size}")

            require(shares.size == 3)

            Log.i("BackupRepository", "Uploading encrypted backup to Google Drive")

            val driveShare = shares[0]
            val backendShare = shares[1]
            val localShare = shares[2]

            uploadEncryptedBackupToDrive(
                accessToken = googleAccessToken,
                encryptedBackup = encryptedBackup
            )

            Log.i("BackupRepository", "Encrypted backup uploaded to Google Drive")

            uploadShareToDrive(
                accessToken = googleAccessToken,
                share = driveShare
            )

            Log.i("BackupRepository", "Drive share uploaded to Google Drive")

            uploadShareToBackend(
                share = backendShare.toShareDto()
            )

            Log.i("BackupRepository", "Backend share uploaded to backend")

            recoveryShareStore.save(
                localShare
            )

            Log.i("BackupRepository", "Local share saved to local storage")
        }catch (e: Exception) {
            throw e
        }
    }

    private suspend fun uploadEncryptedBackupToDrive(
        accessToken: String,
        encryptedBackup: ByteArray
    ) {
        driveRepository.uploadBackup(
            accessToken,
            encryptedBackup
        )
    }

    private suspend fun uploadShareToDrive(
        accessToken: String,
        share: Share
    ) {
        driveRepository.uploadShare(
            accessToken,
            share
        )
    }
}