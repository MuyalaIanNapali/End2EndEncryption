package org.e2ee.client.ui.elements

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.offset
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.outlined.ArrowBack
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import org.e2ee.client.R

@Composable
fun HeaderSection(
    title: String,
    subtitle: String,
    showBackButton: Boolean = false,
    onBackClick: () -> Unit = {}
) {
    // 196 dp tall header — the card below will visually overlap the bottom
    // 28 dp of it (matching the card's topStart/topEnd corner radius).
    Box(
        modifier = Modifier
            .fillMaxWidth()
            // Add extra height so text isn't too close to the rounded card edge
            .height(196.dp)
            .background(MaterialTheme.colorScheme.secondary)
    ) {
        // Decorative circle accent
        Box(
            modifier = Modifier
                .size(260.dp)
                .offset(x = 80.dp, y = (-40).dp)
                .background(
                    MaterialTheme.colorScheme.onSecondary.copy(alpha = 0.04f),
                    CircleShape
                )
        )

        if (showBackButton) {
            IconButton(
                onClick = onBackClick,
                modifier = Modifier
                    .padding(start = 22.dp, top = 38.dp)
                    .size(34.dp)
                    .border(
                        width = 1.dp,
                        color = MaterialTheme.colorScheme.primary,
                        shape = CircleShape
                    )
            ) {
                Icon(
                    imageVector = Icons.AutoMirrored.Outlined.ArrowBack,
                    contentDescription = stringResource(R.string.back_content_description),
                    tint = MaterialTheme.colorScheme.primary,
                    modifier = Modifier.size(18.dp)
                )
            }
        }

        // Title + subtitle — sits in the upper portion so the card overlaps
        // the empty space beneath, not the text
        Column(
            modifier = Modifier.padding(start = 32.dp, top = 80.dp)
        ) {
            Text(
                text = title,
                color = MaterialTheme.colorScheme.onSecondary,
                fontSize = 26.sp,
                fontWeight = FontWeight.Bold,
                lineHeight = 31.sp
            )

            Spacer(modifier = Modifier.height(8.dp))

            Text(
                text = subtitle,
                color = MaterialTheme.colorScheme.onSecondary.copy(alpha = 0.55f),
                fontSize = 13.sp
            )
        }
    }
}