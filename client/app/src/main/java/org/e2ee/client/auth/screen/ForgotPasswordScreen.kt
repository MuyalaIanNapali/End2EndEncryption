package org.e2ee.client.auth.screen

import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable

@Composable
fun ForgotPasswordScreen(
    onBackClick: () -> Unit
) {
    // Your forgot password UI here

    TextButton(
        onClick = onBackClick
    ) {
        Text("Back to Login")
    }
}