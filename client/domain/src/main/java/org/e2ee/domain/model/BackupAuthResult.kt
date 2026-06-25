package org.e2ee.domain.model

sealed interface BackupAuthResult {

    data object Success : BackupAuthResult

    data object NoCredential : BackupAuthResult

    data object Cancelled : BackupAuthResult

    data class ConsentRequired(
        val request: DriveConsentRequest
    ) : BackupAuthResult

    data class Error(
        val throwable: Throwable
    ) : BackupAuthResult
}