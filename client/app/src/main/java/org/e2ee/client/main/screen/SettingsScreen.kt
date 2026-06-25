package org.e2ee.client.main.screen

import android.app.Activity
import android.content.Intent
import android.provider.Settings
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.IntentSenderRequest
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.outlined.AccountCircle
import androidx.compose.material.icons.outlined.Backup
import androidx.compose.material.icons.outlined.CheckCircle
import androidx.compose.material.icons.outlined.ErrorOutline
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Switch
import androidx.compose.material3.SwitchDefaults
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.hilt.lifecycle.viewmodel.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.google.android.gms.auth.api.identity.Identity
import org.e2ee.client.main.viewmodel.SettingsViewModel

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SettingsScreen(
    modifier: Modifier = Modifier,
    onBackClick: () -> Unit = {},
    viewModel: SettingsViewModel = hiltViewModel()
) {
    val uiState by viewModel.uiState.collectAsStateWithLifecycle()
    val context = LocalContext.current

    val consentLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.StartIntentSenderForResult()
    ) { result ->
        if (result.resultCode == Activity.RESULT_OK) {
            // Extract the Drive access token from the consent result intent
            val data: android.content.Intent? = result.data
            val authorizationResult = runCatching {
                Identity.getAuthorizationClient(context)
                    .getAuthorizationResultFromIntent(data ?: Intent())
            }.getOrNull()

            val driveToken = authorizationResult?.accessToken
            if (driveToken != null) {
                viewModel.onConsentGranted(driveToken)
            } else {
                // Consent screen returned OK but no token — treat as error
                viewModel.onConsentDenied()
            }
        } else {
            viewModel.onConsentDenied()
        }
    }

    LaunchedEffect(Unit) {
        viewModel.consentRequests.collect { request ->
            consentLauncher.launch(
                IntentSenderRequest.Builder(request.pendingIntent.intentSender).build()
            )
        }
    }

    val primaryColor = Color(0xFF172237)
    val accentColor = Color(0xFF356DF3)

    if (uiState.showNoAccountDialog) {
        AlertDialog(
            onDismissRequest = { viewModel.dismissNoAccountDialog() },
            icon = {
                Icon(
                    imageVector = Icons.Outlined.AccountCircle,
                    contentDescription = null,
                    tint = accentColor,
                    modifier = Modifier.size(32.dp)
                )
            },
            title = { Text("No Google Account Found", fontWeight = FontWeight.SemiBold) },
            text = {
                Text(
                    "A Google account is required for Drive backup. " +
                            "Add a Google account in your device settings, then try again.",
                    lineHeight = 20.sp
                )
            },
            confirmButton = {
                TextButton(onClick = {
                    viewModel.dismissNoAccountDialog()
                    context.startActivity(
                        Intent(Settings.ACTION_ADD_ACCOUNT).apply {
                            putExtra(Settings.EXTRA_ACCOUNT_TYPES, arrayOf("com.google"))
                        }
                    )
                }) { Text("Add Account", color = accentColor) }
            },
            dismissButton = {
                TextButton(onClick = { viewModel.dismissNoAccountDialog() }) {
                    Text("Cancel", color = Color.Gray)
                }
            }
        )
    }

    Scaffold(
        modifier = modifier,
        topBar = {
            TopAppBar(
                title = { Text("Settings", fontWeight = FontWeight.SemiBold, color = Color.White) },
                navigationIcon = {
                    IconButton(onClick = onBackClick) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back", tint = Color.White)
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(containerColor = primaryColor)
            )
        },
        containerColor = Color(0xFFF5F7FA)
    ) { paddingValues ->

        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(paddingValues)
                .padding(horizontal = 16.dp, vertical = 20.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {

            Text(
                text = "DATA & PRIVACY",
                fontSize = 11.sp,
                fontWeight = FontWeight.SemiBold,
                color = Color(0xFF8A94A6),
                letterSpacing = 0.8.sp,
                modifier = Modifier.padding(horizontal = 4.dp, vertical = 4.dp)
            )

            Box(
                modifier = Modifier
                    .fillMaxWidth()
                    .background(Color.White, RoundedCornerShape(16.dp))
                    .padding(horizontal = 20.dp, vertical = 16.dp)
            ) {
                Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {

                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.SpaceBetween
                    ) {
                        Row(
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.spacedBy(12.dp),
                            modifier = Modifier.weight(1f)
                        ) {
                            Icon(
                                imageVector = Icons.Outlined.Backup,
                                contentDescription = null,
                                tint = accentColor,
                                modifier = Modifier.size(24.dp)
                            )
                            Column {
                                Text(
                                    text = "Google Drive Backup",
                                    fontSize = 15.sp,
                                    fontWeight = FontWeight.Medium,
                                    color = primaryColor
                                )
                                Text(
                                    text = "Encrypted daily backup at 6 AM",
                                    fontSize = 12.sp,
                                    color = Color(0xFF8A94A6)
                                )
                            }
                        }

                        if (uiState.isBackupLoading) {
                            CircularProgressIndicator(
                                modifier = Modifier.size(24.dp),
                                strokeWidth = 2.dp,
                                color = accentColor
                            )
                        } else {
                            Switch(
                                checked = uiState.isBackupEnabled,
                                onCheckedChange = { enabled ->
                                    viewModel.onBackupToggled(
                                        enabled = enabled,
                                        activity = context as Activity
                                    )
                                },
                                colors = SwitchDefaults.colors(
                                    checkedThumbColor = Color.White,
                                    checkedTrackColor = accentColor
                                )
                            )
                        }
                    }

                    if (uiState.backupSuccess) {
                        Spacer(modifier = Modifier.height(8.dp))
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .background(Color(0xFFECFDF5), RoundedCornerShape(8.dp))
                                .padding(horizontal = 12.dp, vertical = 8.dp),
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.spacedBy(8.dp)
                        ) {
                            Icon(Icons.Outlined.CheckCircle, null, tint = Color(0xFF22C55E), modifier = Modifier.size(16.dp))
                            Text("Backup enabled. First run at 6 AM.", fontSize = 12.sp, color = Color(0xFF16A34A), fontWeight = FontWeight.Medium)
                        }
                    }

                    if (uiState.backupError != null) {
                        Spacer(modifier = Modifier.height(8.dp))
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .background(Color(0xFFFEF2F2), RoundedCornerShape(8.dp))
                                .padding(horizontal = 12.dp, vertical = 8.dp),
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.spacedBy(8.dp)
                        ) {
                            Icon(Icons.Outlined.ErrorOutline, null, tint = Color(0xFFEF4444), modifier = Modifier.size(16.dp))
                            Text(uiState.backupError!!, fontSize = 12.sp, color = Color(0xFFDC2626), fontWeight = FontWeight.Medium)
                        }
                    }
                }
            }

            Text(
                text = "Your backup is end-to-end encrypted. The decryption key is split across Google Drive, our server, and your device using Shamir secret sharing — no single party can access your data.",
                fontSize = 12.sp,
                color = Color(0xFF8A94A6),
                lineHeight = 18.sp,
                modifier = Modifier.padding(horizontal = 4.dp)
            )
        }
    }
}