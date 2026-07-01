package org.e2ee.data.repository.backup

import android.util.Log
import org.e2ee.crypto.backup.BackupDB
import org.e2ee.common.Share
import org.e2ee.data.local.database.serializeBackup
import org.e2ee.data.local.user.share.RecoveryShareStore
import org.e2ee.data.remote.network.ApiResult
import org.e2ee.data.remote.shares.RemoteShareRepository
import org.e2ee.data.remote.shares.dto.ShareDto
import org.e2ee.data.remote.shares.dto.ShareResponse
import org.e2ee.data.remote.shares.dto.UpdateSharesRequest
import org.e2ee.data.remote.shares.dto.toShare
import org.e2ee.data.remote.shares.dto.toShareDto
import javax.inject.Inject
import kotlin.math.log

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

    suspend fun restoreBackup(
        googleAccessToken: String
    ) {
        val encryptedBackup = downloadEncryptedBackupFromDrive(googleAccessToken)
            ?: throw IllegalStateException("No backup found on Google Drive")

        Log.i("BackupRepository", "Encrypted backup downloaded from Google Drive, size: ${encryptedBackup.size}")

        val shares = buildList {
            runCatching { recoveryShareStore.load() }.getOrNull()?.let { add(it) }
            runCatching { downloadShareFromDrive(googleAccessToken) }.getOrNull()?.let { add(it) }
            runCatching { downloadShareFromBackend().share.toShareDto().toShare() }.getOrNull()?.let { add(it) }
        }

        Log.i("BackupRepository", "Shares collected for restoration, count: ${shares.size}")

        require(shares.size >= 2) {
            "Not enough recovery shares to restore (found ${shares.size}, need 2)"
        }

        val decryptedBackup = BackupDB().decryptDatabaseBackup(encryptedBackup, shares)

        backupExporter.import(decryptedBackup)
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

    private suspend fun downloadEncryptedBackupFromDrive(
        accessToken: String
    ): ByteArray? {
        return driveRepository.downloadBackup(accessToken)
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

    private suspend fun downloadShareFromDrive(
        accessToken: String
    ): Share? {
        return driveRepository.downloadShare(accessToken)
    }

    suspend fun downloadShareFromBackend(): ShareResponse {
        return when (val result = remoteShareRepository.getUserShare()) {
            is ApiResult.Success ->{
                Log.i("BackupRepository", "Successfully downloaded share from backend: ${result.data}")
                result.data
            }
            is ApiResult.Error -> {
                Log.i("BackupRepository", "Error downloading share from backend: ${result.message}")
                throw IllegalStateException(result.message)
            }
            is ApiResult.NetworkError -> {
                Log.i("BackupRepository", "Network error downloading share from backend: ${result.message}")
                throw IllegalStateException(result.message)}
            is ApiResult.UnknownError -> {
                Log.i(
                    "BackupRepository",
                    "Unknown error downloading share from backend: ${result.message}"
                )
                throw IllegalStateException(result.message)
            }
            }
        }
    }