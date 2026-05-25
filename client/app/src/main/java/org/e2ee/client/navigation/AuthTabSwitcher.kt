package org.e2ee.client.navigation

import androidx.compose.animation.animateColorAsState
import androidx.compose.animation.core.animateDpAsState
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.shadow
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.unit.dp

@Composable
fun AuthTabSwitcher(
    selectedRoute: Route?,
    onLoginClick: () -> Unit,
    onRegisterClick: () -> Unit,
    modifier: Modifier = Modifier
) {
    val isLoginSelected = selectedRoute == Route.Auth.Login

    Row(
        modifier = modifier
            .fillMaxWidth()
            .height(56.dp)
            .background(
                color = Color(0xFFE4E8EF),
                shape = RoundedCornerShape(28.dp)
            )
            .padding(4.dp)
    ) {
        AuthTabItem(
            text = "Login",
            selected = isLoginSelected,
            onClick = onLoginClick,
            modifier = Modifier.weight(1f)
        )

        AuthTabItem(
            text = "Register",
            selected = !isLoginSelected,
            onClick = onRegisterClick,
            modifier = Modifier.weight(1f)
        )
    }
}

@Composable
private fun AuthTabItem(
    text: String,
    selected: Boolean,
    onClick: () -> Unit,
    modifier: Modifier = Modifier
) {
    val backgroundColor by animateColorAsState(
        targetValue = if (selected) Color.White else Color.Transparent,
        label = "tabBackgroundColor"
    )

    val textColor by animateColorAsState(
        targetValue = if (selected) Color.Black else Color(0xFF6B7280),
        label = "tabTextColor"
    )

    val elevation by animateDpAsState(
        targetValue = if (selected) 4.dp else 0.dp,
        label = "tabElevation"
    )

    Box(
        modifier = modifier
            .height(48.dp)
            .shadow(
                elevation = elevation,
                shape = RoundedCornerShape(24.dp)
            )
            .background(
                color = backgroundColor,
                shape = RoundedCornerShape(24.dp)
            )
            .clickable {
                onClick()
            },
        contentAlignment = Alignment.Center
    ) {
        Text(
            text = text,
            color = textColor,
            style = MaterialTheme.typography.bodyMedium
        )
    }
}