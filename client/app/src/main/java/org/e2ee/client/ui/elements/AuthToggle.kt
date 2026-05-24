package org.e2ee.client.ui.elements

import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import org.e2ee.client.navigation.Route

@Composable
fun AuthToggle(
    selectedRoute: Route.Auth?,
    onLoginClick: () -> Unit,
    onRegisterClick: () -> Unit
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .height(56.dp)
            .padding(vertical = 8.dp)
    ) {
        AppButton(
            onClick = onLoginClick,
            buttonText = "Login",
            modifier = Modifier.width(200.dp)
        ) {

        }

        AppButton(
            onClick = onRegisterClick,
            buttonText = "Register",
            modifier = Modifier.width(200.dp)
        ) {

        }
    }
}

@Preview
@Composable
fun AuthTogglePreview() {
    AuthToggle(
        selectedRoute = Route.Auth,
        onLoginClick = {},
        onRegisterClick = {}
    )
}