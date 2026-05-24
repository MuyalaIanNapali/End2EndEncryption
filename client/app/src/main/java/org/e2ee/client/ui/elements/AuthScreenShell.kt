package org.e2ee.client.ui.elements

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import org.e2ee.client.navigation.Route

@Composable
fun AuthScreenShell(
    modifier: Modifier = Modifier,
    selectedRoute: Route.Auth?,
    onLoginClick: () -> Unit,
    onRegisterClick: () -> Unit,
    showToggle: Boolean = true,
    content: @Composable (Modifier) -> Unit
) {
    Column(
        modifier = modifier
    ) {
        // Top dark header area
        AuthHeader(
            selectedRoute = selectedRoute
        )

        // White rounded card area
        Column(
            modifier = Modifier
                .weight(1f)
                .padding(horizontal = 24.dp)
        ) {
            if (showToggle) {
                AuthToggle(
                    selectedRoute = selectedRoute,
                    onLoginClick = onLoginClick,
                    onRegisterClick = onRegisterClick
                )
            }

            content(
                Modifier.weight(1f)
            )
        }
    }
}

@Composable
fun AuthHeader(
    selectedRoute: Route.Auth?
) {
    Column(
        modifier = Modifier
            .padding(24.dp)
    ) {
        Text(
            text = when (selectedRoute) {
                Route.Auth.Login -> "Welcome Back"
                Route.Auth.Register -> "Create Account"
                Route.Auth.ForgotPassword -> "Forgot Password"
                else -> "Welcome"
            },
            style = MaterialTheme.typography.headlineMedium,
            color = MaterialTheme.colorScheme.onPrimary
        )

        Text(
            text = when (selectedRoute) {
                Route.Auth.Login -> "Please login to your account"
                Route.Auth.Register -> "Please fill the form to create an account"
                Route.Auth.ForgotPassword -> "Enter your email to reset password"
                else -> "Please login or register to continue"
            },
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onPrimary
        )
    }
}