package org.e2ee.data.repository.backup

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
            val (encryptedBackup, shares) =
                createEncryptedBackup()

            require(shares.size == 3)

            val driveShare = shares[0]
            val backendShare = shares[1]
            val localShare = shares[2]

            uploadEncryptedBackupToDrive(
                accessToken = googleAccessToken,
                encryptedBackup = encryptedBackup
            )

            uploadShareToDrive(
                accessToken = googleAccessToken,
                share = driveShare
            )

            uploadShareToBackend(
                share = backendShare.toShareDto()
            )

            recoveryShareStore.save(
                localShare
            )
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