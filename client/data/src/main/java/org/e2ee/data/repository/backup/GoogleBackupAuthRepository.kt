package org.e2ee.data.repository.backup

import android.app.Activity
import android.util.Log
import androidx.credentials.CredentialManager
import androidx.credentials.CustomCredential
import androidx.credentials.GetCredentialRequest
import androidx.credentials.exceptions.GetCredentialCancellationException
import androidx.credentials.exceptions.NoCredentialException
import com.google.android.gms.auth.api.identity.AuthorizationRequest
import com.google.android.gms.auth.api.identity.AuthorizationResult
import com.google.android.gms.auth.api.identity.Identity
import com.google.android.gms.common.api.Scope
import com.google.android.libraries.identity.googleid.GetGoogleIdOption
import com.google.android.libraries.identity.googleid.GetSignInWithGoogleOption
import com.google.android.libraries.identity.googleid.GoogleIdTokenCredential
import kotlinx.coroutines.suspendCancellableCoroutine
import org.e2ee.domain.model.BackupAuthResult
import org.e2ee.domain.model.DomainResult
import org.e2ee.domain.model.DriveConsentRequest
import org.e2ee.domain.repository.BackupAuthRepository
import java.security.SecureRandom
import java.util.Base64
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException

class GoogleBackupAuthRepository(
    private val webClientId: String,
    private val backupRepository: BackupRepository
) : BackupAuthRepository {

    override suspend fun signInAndAuthorize(
        activity: Activity
    ): BackupAuthResult {
        val credentialManager = CredentialManager.create(activity)

        // Step 1: silent check — previously authorized accounts via Credential Manager.
        // This succeeds instantly if the user already granted access before.
        val silentResult = attemptSilentSignIn(credentialManager, activity)

        // Step 2: silent succeeded — go straight to Drive authorization.
        if (silentResult is SignInResult.Success) {
            Log.i(TAG, "Silent sign-in succeeded for ${silentResult.email}")
            return authorizeDrive(activity)
        }

        // Step 3: no prior authorization or no Credential Manager account —
        // show the full Google account picker (GetSignInWithGoogleOption always
        // presents all accounts added to the device, not just previously-authorized ones).
        Log.i(TAG, "Silent sign-in returned ${silentResult::class.simpleName}, showing account picker")
        val pickerResult = attemptPickerSignIn(credentialManager, activity)

        return when (pickerResult) {
            is SignInResult.Success -> {
                Log.i(TAG, "Picker sign-in succeeded for ${pickerResult.email}")
                authorizeDrive(activity)
            }
            is SignInResult.NoCredential -> BackupAuthResult.NoCredential
            is SignInResult.Cancelled -> BackupAuthResult.Cancelled
            is SignInResult.Error -> BackupAuthResult.Error(pickerResult.throwable)
        }
    }

    override suspend fun backupNow(activity: Activity): DomainResult<Boolean> {
        return when (val token = getDriveAccessToken(activity)) {   // the helper from earlier
            is TokenResult.Success -> {
                backupRepository.backup(token.accessToken)
                DomainResult.Success(true)
            }
            is TokenResult.ConsentRequired ->
                DomainResult.Error("Drive authorization required")
            is TokenResult.Error ->
                DomainResult.Error(token.throwable.message ?: "Authorization failed")
        }
    }

    override suspend fun restoreBackup(activity: Activity): DomainResult<Boolean> {
        // Same front door as "enable backup": sign in, then authorize Drive.
        when (val auth = signInAndAuthorize(activity)) {
            is BackupAuthResult.Success -> {
                // Authorized with no UI needed — fetch a fresh token and restore.
            }
            is BackupAuthResult.ConsentRequired ->
                return DomainResult.Error("Drive authorization required")
            is BackupAuthResult.NoCredential ->
                return DomainResult.Error("No Google account available")
            is BackupAuthResult.Cancelled ->
                return DomainResult.Error("Sign-in cancelled")
            is BackupAuthResult.Error ->
                return DomainResult.Error(auth.throwable.message ?: "Authorization failed")
        }

        return when (val token = getDriveAccessToken(activity)) {
            is TokenResult.Success -> {
                try {
                    backupRepository.restoreBackup(token.accessToken)
                    DomainResult.Success(true)
                } catch (e: Exception) {
                    Log.e(TAG, "Restore failed", e)
                    DomainResult.Error(e.message ?: "Restore failed")
                }
            }
            is TokenResult.ConsentRequired ->
                DomainResult.Error("Drive authorization required")
            is TokenResult.Error ->
                DomainResult.Error(token.throwable.message ?: "Authorization failed")
        }
    }


    /**
     * Tries to sign in silently using a previously authorized Google account.
     * Uses GetGoogleIdOption with filterByAuthorizedAccounts=true — no UI shown,
     * returns NoCredential immediately if nothing is cached.
     */
    private suspend fun attemptSilentSignIn(
        credentialManager: CredentialManager,
        activity: Activity
    ): SignInResult {
        return try {
            val googleIdOption = GetGoogleIdOption.Builder()
                .setFilterByAuthorizedAccounts(true)
                .setServerClientId(webClientId)
                .setNonce(generateSecureRandomNonce())
                .build()

            val request = GetCredentialRequest.Builder()
                .addCredentialOption(googleIdOption)
                .build()

            val result = credentialManager.getCredential(request = request, context = activity)
            val credential = result.credential as? CustomCredential
                ?: return SignInResult.Error(IllegalStateException("Unexpected credential type"))

            val googleCredential = GoogleIdTokenCredential.createFrom(credential.data)
            SignInResult.Success(email = googleCredential.id)

        } catch (e: NoCredentialException) {
            SignInResult.NoCredential
        } catch (e: GetCredentialCancellationException) {
            SignInResult.Cancelled
        } catch (e: Exception) {
            SignInResult.Error(e)
        }
    }

    /**
     * Shows the explicit Google Sign-In bottom sheet that lists ALL accounts
     * added to the device — not filtered by prior Credential Manager history.
     * This is the right call for a user-initiated "enable backup" action.
     */
    private suspend fun attemptPickerSignIn(
        credentialManager: CredentialManager,
        activity: Activity
    ): SignInResult {
        return try {
            val signInWithGoogleOption = GetSignInWithGoogleOption.Builder(
                serverClientId = webClientId
            )
                .setNonce(generateSecureRandomNonce())
                .build()

            val request = GetCredentialRequest.Builder()
                .addCredentialOption(signInWithGoogleOption)
                .build()

            val result = credentialManager.getCredential(request = request, context = activity)
            val credential = result.credential as? CustomCredential
                ?: return SignInResult.Error(IllegalStateException("Unexpected credential type"))

            val googleCredential = GoogleIdTokenCredential.createFrom(credential.data)
            SignInResult.Success(email = googleCredential.id)

        } catch (e: NoCredentialException) {
            SignInResult.NoCredential
        } catch (e: GetCredentialCancellationException) {
            SignInResult.Cancelled
        } catch (e: Exception) {
            SignInResult.Error(e)
        }
    }

    private suspend fun authorizeDrive(activity: Activity): BackupAuthResult {
        return when (val token = getDriveAccessToken(activity)) {
            is TokenResult.Success -> BackupAuthResult.Success
            is TokenResult.ConsentRequired -> BackupAuthResult.ConsentRequired(
                DriveConsentRequest(pendingIntent = token.pendingIntent)
            )
            is TokenResult.Error -> BackupAuthResult.Error(token.throwable)
        }
    }

    private fun generateSecureRandomNonce(byteLength: Int = 32): String {
        val randomBytes = ByteArray(byteLength)
        SecureRandom.getInstanceStrong().nextBytes(randomBytes)
        return Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes)
    }

    private sealed interface SignInResult {
        data class Success(val email: String) : SignInResult
        data object NoCredential : SignInResult
        data object Cancelled : SignInResult
        data class Error(val throwable: Throwable) : SignInResult
    }

    companion object {
        private const val TAG = "DriveBackup"
    }
}

