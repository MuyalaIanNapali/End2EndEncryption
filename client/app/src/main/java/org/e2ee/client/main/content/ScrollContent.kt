package org.e2ee.client.main.content

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import org.e2ee.client.models.ChatMessageUi
import org.e2ee.client.ui.elements.MessageBubble

@Composable
fun ScrollContent(
    innerPadding: PaddingValues,
    messages: List<ChatMessageUi>
) {
    val listState = rememberLazyListState()

    LaunchedEffect(messages.size) {
        if (messages.isNotEmpty()) {
            listState.animateScrollToItem(messages.lastIndex)
        }
    }

    LazyColumn(
        state = listState,
        modifier = Modifier
            .fillMaxSize()
            .padding(innerPadding)
            .padding(horizontal = 12.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp),
        contentPadding = PaddingValues(
            top = 8.dp,
            bottom = 16.dp
        )
    ) {
        items(
            items = messages,
            key = { it.id }
        ) { message ->
            MessageBubble(
                messageText = message.text,
                timestamp = message.timestamp,
                isMine = message.isSentByUser
            )
        }
    }
}