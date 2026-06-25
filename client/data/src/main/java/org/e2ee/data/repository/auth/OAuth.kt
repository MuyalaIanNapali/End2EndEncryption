package org.e2ee.data.repository.auth

import android.app.Activity
import android.content.Context
import android.content.Intent
import androidx.activity.result.ActivityResultLauncher
import androidx.activity.result.IntentSenderRequest
import com.google.android.gms.common.api.Scope
import com.google.android.gms.auth.api.identity.Identity
import com.google.android.gms.auth.api.identity.AuthorizationClient
import com.google.android.gms.auth.api.identity.AuthorizationRequest
import com.google.android.gms.auth.api.identity.AuthorizationResult

class OAuth(
    private val context: Context
) {

    private val authorizationClient: AuthorizationClient =
        Identity.getAuthorizationClient(context)

    /**
     * Step 1: Build authorization request
     */
    fun buildAuthorizationRequest(
        serverClientId: String? = null
    ): AuthorizationRequest {

        val scopes: List<Scope> = listOf(
            Scope("https://www.googleapis.com/auth/drive.appdata")
        )

        val builder = AuthorizationRequest.builder()
            .setRequestedScopes(scopes)

        if (serverClientId != null) {
            builder.requestOfflineAccess(serverClientId)
        }

        return builder.build()
    }

    /**
     * Step 2: Launch authorization UI safely
     */
    fun authorize(
        launcher: ActivityResultLauncher<IntentSenderRequest>,
        request: AuthorizationRequest
    ) {

        authorizationClient
            .authorize(request)
            .addOnSuccessListener { result ->

                if (result.hasResolution()) {
                    // Use safe-call on pendingIntent to avoid unsafe access on nullable receiver
                    result.pendingIntent?.let { pending ->
                        val intentSenderRequest =
                            IntentSenderRequest.Builder(pending.intentSender).build()

                        launcher.launch(intentSenderRequest)
                    }
                }
                // else: already authorized → no UI needed

            }
            .addOnFailureListener {
                throw RuntimeException("Google Drive authorization failed", it)
            }
    }

    /**
     * Step 3: Handle result safely
     */
    fun handleAuthorizationResult(data: Intent?): AuthorizationResult {

        requireNotNull(data) {
            "Authorization intent data is null"
        }

        return authorizationClient
            .getAuthorizationResultFromIntent(data)
    }

    /**
     * Step 4: Extract token (NON-null after success)
     */
    fun extractAccessToken(result: AuthorizationResult): String {

        return result.accessToken
            ?: throw IllegalStateException("Access token is null after successful authorization")
    }
}