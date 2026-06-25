package org.e2ee.client.splash

import androidx.compose.animation.core.Animatable
import androidx.compose.animation.core.tween
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.scale
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import org.e2ee.client.R
import org.e2ee.client.ui.theme.Blue500
import org.e2ee.client.ui.theme.Navy900

/**
 * Full-screen branded splash shown while session auto-login is in progress.
 * Replaces the raw CircularProgressIndicator in NavigationRoot.
 */
@Composable
fun AppSplashScreen(modifier: Modifier = Modifier) {
    val scale = remember { Animatable(0.6f) }

    LaunchedEffect(Unit) {
        scale.animateTo(
            targetValue = 1f,
            animationSpec = tween(durationMillis = 400)
        )
    }

    Box(
        modifier = modifier
            .fillMaxSize()
            .background(
                Brush.verticalGradient(
                    colors = listOf(Navy900, Color(0xFF1E2D47))
                )
            ),
        contentAlignment = Alignment.Center
    ) {
        // Subtle decorative circle
        Box(
            modifier = Modifier
                .size(320.dp)
                .background(
                    Color.White.copy(alpha = 0.03f),
                    CircleShape
                )
        )

        Column(
            modifier = Modifier.scale(scale.value),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            // Icon circle
            Surface(
                modifier = Modifier.size(88.dp),
                shape = CircleShape,
                color = Blue500,
                shadowElevation = 12.dp
            ) {
                Box(contentAlignment = Alignment.Center) {
                    Text(
                        text = "VC",
                        color = Color.White,
                        fontWeight = FontWeight.ExtraBold,
                        fontSize = 28.sp
                    )
                }
            }

            Spacer(modifier = Modifier.height(24.dp))

            Text(
                text = stringResource(R.string.app_name),
                color = Color.White,
                fontWeight = FontWeight.Bold,
                fontSize = 30.sp,
                letterSpacing = 0.5.sp
            )

            Spacer(modifier = Modifier.height(8.dp))

            Text(
                text = stringResource(R.string.splash_tagline),
                color = Color.White.copy(alpha = 0.6f),
                style = MaterialTheme.typography.bodyMedium,
                letterSpacing = 0.3.sp
            )
        }
    }
}
