package org.e2ee.client.ui.elements

import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Person
import androidx.compose.material3.Icon
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import org.e2ee.client.navigation.Route

@Composable
private fun AuthNavigationBar(
    selectedRoute: Route.Auth?,
    onLoginClick: () -> Unit,
    onRegisterClick: () -> Unit
) {
    NavigationBar {
        NavigationBarItem(
            selected = selectedRoute == Route.Auth.Login,
            onClick = onLoginClick,
            icon = {
                Icon(
                    imageVector = Icons.Default.Lock,
                    contentDescription = null
                )
            },
            label = {
                Text(text = "Login")
            }
        )

        NavigationBarItem(
            selected = selectedRoute == Route.Auth.Register,
            onClick = onRegisterClick,
            icon = {
                Icon(
                    imageVector = Icons.Default.Person,
                    contentDescription = null
                )
            },
            label = {
                Text(text = "Register")
            }
        )
    }
}
