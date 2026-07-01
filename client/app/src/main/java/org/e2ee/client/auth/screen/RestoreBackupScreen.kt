package org.e2ee.client.auth.screen

import android.app.Activity
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.SettingsBackupRestore
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.hilt.lifecycle.viewmodel.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import org.e2ee.client.auth.viewmodel.RestoreBackupViewModel

@Composable
fun RestoreBackupScreen(
    modifier: Modifier = Modifier,
    onFinished: () -> Unit,
    viewModel: RestoreBackupViewModel = hiltViewModel()
) {
    val uiState by viewModel.uiState.collectAsStateWithLifecycle()
    val context = LocalContext.current

    // Restore succeeded or the user skipped -> move on to the main app.
    LaunchedEffect(uiState.isFinished) {
        if (uiState.isFinished) onFinished()
    }

    Column(
        modifier = modifier
            .fillMaxSize()
            .padding(horizontal = 28.dp),
        verticalArrangement = Arrangement.Center,
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        Icon(
            imageVector = Icons.Outlined.SettingsBackupRestore,
            contentDescription = null,
            tint = MaterialTheme.colorScheme.primary,
            modifier = Modifier.size(56.dp)
        )

        Spacer(Modifier.height(20.dp))

        Text(
            text = "Restore your data?",
            fontSize = 22.sp,
            fontWeight = FontWeight.SemiBold,
            color = MaterialTheme.colorScheme.onBackground,
            textAlign = TextAlign.Center
        )

        Spacer(Modifier.height(10.dp))

        Text(
            text = "If you previously backed up to Google Drive, you can restore your " +
                    "chats and contacts to this device now. You can also skip and do this later.",
            fontSize = 14.sp,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            lineHeight = 20.sp,
            textAlign = TextAlign.Center
        )

        if (uiState.errorMessage != null) {
            Spacer(Modifier.height(16.dp))
            Text(
                text = uiState.errorMessage!!,
                fontSize = 13.sp,
                color = MaterialTheme.colorScheme.error,
                textAlign = TextAlign.Center
            )
        }

        Spacer(Modifier.height(32.dp))

        if (uiState.isRestoring) {
            CircularProgressIndicator(color = MaterialTheme.colorScheme.primary)
            Spacer(Modifier.height(12.dp))
            Text(
                text = "Restoring…",
                fontSize = 13.sp,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        } else {
            Button(
                onClick = { viewModel.restore(context as Activity) },
                modifier = Modifier.fillMaxWidth()
            ) {
                Text(if (uiState.errorMessage != null) "Try again" else "Restore from backup")
            }

            Spacer(Modifier.height(8.dp))

            TextButton(
                onClick = { viewModel.skip() },
                modifier = Modifier.fillMaxWidth()
            ) {
                Text("Skip for now")
            }
        }
    }
}