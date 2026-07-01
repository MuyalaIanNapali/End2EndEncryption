package org.e2ee.data.repository.backup

import org.e2ee.common.Share

interface GoogleDriveRepository {

    suspend fun uploadBackup(
        accessToken: String,
        encryptedBackup: ByteArray
    )

    suspend fun uploadShare(
        accessToken: String,
        share: Share
    )

    suspend fun downloadBackup(accessToken: String): ByteArray?
    suspend fun downloadShare(accessToken: String): Share?
}