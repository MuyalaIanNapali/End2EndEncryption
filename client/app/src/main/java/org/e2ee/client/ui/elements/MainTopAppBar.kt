package org.e2ee.client.ui.elements

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.offset
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.outlined.Logout
import androidx.compose.material.icons.outlined.Logout
import androidx.compose.material.icons.outlined.Settings
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

@Composable
fun MainTopAppBar(
    title: String,
    height: Dp,
    collapseProgress: Float,
    onLogOutClicked: () -> Unit
) {
    Box(
        modifier = Modifier
            .fillMaxWidth()
            .height(height)
            .background(Color(0xFF172237))
    ) {
        Box(
            modifier = Modifier
                .size(260.dp)
                .offset(x = 90.dp, y = (-40).dp)
                .background(
                    Color.White.copy(alpha = 0.04f),
                    CircleShape
                )
        )

        Text(
            text = title,
            color = Color.White,
            fontSize = if (collapseProgress < 0.5f) 28.sp else 22.sp,
            fontWeight = FontWeight.Bold,
            modifier = Modifier
                .align(
                    if (collapseProgress < 0.5f) {
                        Alignment.BottomStart
                    } else {
                        Alignment.CenterStart
                    }
                )
                .padding(
                    start = 32.dp,
                    bottom = if (collapseProgress < 0.5f) 38.dp else 0.dp
                )
        )

        IconButton(
            onClick = onLogOutClicked,
            modifier = Modifier
                .align(Alignment.TopEnd)
                .padding(top = 34.dp, end = 20.dp)
        ) {
            Icon(
                imageVector = Icons.AutoMirrored.Outlined.Logout,
                contentDescription = "Logout",
                tint = Color(0xFF356DF3),
                modifier = Modifier.size(24.dp)
            )
        }
    }
}

@Preview
@Composable
fun MainTopAppBarPreview() {
    MainTopAppBar(
        title = "E2EE Messenger",
        height = 200.dp,
        collapseProgress = 0.3f,
        onLogOutClicked = {}
    )
}