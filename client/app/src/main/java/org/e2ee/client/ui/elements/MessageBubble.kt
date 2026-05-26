package org.e2ee.client.ui.elements

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp

@Composable
fun MessageBubble(
    modifier: Modifier = Modifier,
    messageText: String,
    timestamp: String,
    isMine: Boolean
) {
    Row(
        modifier = modifier
            .fillMaxWidth()
            .padding(horizontal = 12.dp, vertical = 4.dp),
        horizontalArrangement = if (isMine) {
            Arrangement.End
        } else {
            Arrangement.Start
        }
    ) {
        Column(
            modifier = Modifier
                .widthIn(max = 280.dp)
                .background(
                    color = if (isMine) {
                        Color(0xFF356DF3)
                    } else {
                        Color(0xFFE9EEF6)
                    },
                    shape = RoundedCornerShape(
                        topStart = 18.dp,
                        topEnd = 18.dp,
                        bottomStart = if (isMine) 18.dp else 4.dp,
                        bottomEnd = if (isMine) 4.dp else 18.dp
                    )
                )
                .padding(horizontal = 14.dp, vertical = 10.dp)
        ) {
            Text(
                text = messageText,
                color = if (isMine) Color.White else Color(0xFF172237),
                style = MaterialTheme.typography.bodyMedium
            )

            Text(
                text = timestamp,
                color = if (isMine) {
                    Color.White.copy(alpha = 0.7f)
                } else {
                    Color(0xFF172237).copy(alpha = 0.55f)
                },
                style = MaterialTheme.typography.labelSmall,
                textAlign = TextAlign.End,
                modifier = Modifier
                    .align(Alignment.End)
                    .padding(top = 4.dp)
            )
        }
    }
}

@Preview
@Composable
fun MessageCardPreview() {
    Column() {
        MessageBubble(
            messageText = "Hello, how are you?",
            timestamp = "12:34 PM",
            isMine = false
        )
        MessageBubble(
            messageText = "I'm good, thanks! How about you?",
            timestamp = "12:35 PM",
            isMine = true
        )
    }
}