package org.e2ee.client.ui.elements

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.Send
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp

@Composable
fun ChatBottomBar(
    modifier: Modifier = Modifier,
    onSendClick: (String) -> Unit = {},
    onTyping: (String) -> Unit = {},
) {
    var message by remember { mutableStateOf("") }

    Row(
        modifier = modifier.padding(8.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(8.dp)
    ) {
        AppTextField(
            modifier = Modifier.weight(1f),
            value = message,
            onValueChange = {
                message = it
                onTyping(it)
            },
            placeholder = "Type a message",
            singleLine = false,
            maxLines = 10
        )

        if (message.isNotBlank()) {
            IconButton(
                onClick = {
                    onSendClick(message)
                    message = ""
                }
            ) {
                Icon(
                    imageVector = Icons.AutoMirrored.Filled.Send,
                    contentDescription = "Send message"
                )
            }
        }
    }
}

@Preview(showBackground = true)
@Composable
fun ChatBottomBarPreview() {
    ChatBottomBar()
}