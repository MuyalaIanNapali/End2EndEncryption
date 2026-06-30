package org.e2ee.data.repository.backup

import android.app.Activity
import com.google.android.gms.auth.api.identity.AuthorizationRequest
import com.google.android.gms.auth.api.identity.AuthorizationResult
import com.google.android.gms.auth.api.identity.Identity
import com.google.android.gms.common.api.Scope
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException

internal sealed interface TokenResult {
    data class Success(val accessToken: String) : TokenResult
    data class ConsentRequired(val pendingIntent: android.app.PendingIntent) : TokenResult
    data class Error(val throwable: Throwable) : TokenResult
}

internal suspend fun getDriveAccessToken(activity: Activity): TokenResult {
    val authorizationClient = Identity.getAuthorizationClient(activity)

    val request = AuthorizationRequest.builder()
        .setRequestedScopes(
            listOf(Scope("https://www.googleapis.com/auth/drive.appdata"))
        )
        .build()

    val result = suspendCancellableCoroutine<AuthorizationResult> { cont ->
        authorizationClient.authorize(request)
            .addOnSuccessListener { cont.resume(it) }
            .addOnFailureListener { cont.resumeWithException(it) }
    }

    return when {
        result.hasResolution() -> TokenResult.ConsentRequired(result.pendingIntent!!)
        result.accessToken != null -> TokenResult.Success(result.accessToken!!)
        else -> TokenResult.Error(IllegalStateException("No access token and no resolution"))
    }
}