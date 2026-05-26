package org.e2ee.client.main.screen

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.navigationBars
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.material3.Scaffold
import androidx.compose.runtime.Composable
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import org.e2ee.client.ui.elements.ChatBottomBar
import org.e2ee.client.ui.elements.ChatTopAppBar
import org.e2ee.client.ui.elements.MessageBubble

@Composable
fun ChatScreen(
    modifier: Modifier = Modifier,
    username: String,
    messages: List<ChatMessageUi>,
    onBackClick: () -> Unit = {},
    onSettingsClick: () -> Unit = {},
    onSendMessage: (String) -> Unit = {}
) {
    Scaffold(
        modifier = modifier,
        topBar = {
            ChatTopAppBar(
                username = username,
                onBackClick = onBackClick,
                onSettingsClick = onSettingsClick
            )
        },
        bottomBar = {
            ChatBottomBar(
                modifier = Modifier
                    .navigationBarsPadding()
                    .imePadding(),
                onSendClick = { message ->
                    onSendMessage(message)
                },
                onTyping = {
                    // Handle typing
                }
            )
        },
        contentWindowInsets = WindowInsets.navigationBars
    ) { innerPadding ->
        ScrollContent(
            innerPadding = innerPadding,
            messages = messages
        )
    }
}

@Composable
fun ScrollContent(
    innerPadding: PaddingValues,
    messages: List<ChatMessageUi>
) {
    val listState = rememberLazyListState()

    LazyColumn(
        state = listState,
        modifier = Modifier
            .fillMaxSize()
            .padding(innerPadding)
            .padding(horizontal = 12.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp),
        contentPadding = PaddingValues(
            top = 8.dp,
            bottom = 8.dp
        ),
        reverseLayout = false
    ) {
        items(
            items = messages,
            key = { it.id }
        ) { message ->
            MessageBubble(
                messageText = message.text,
                timestamp = message.timestamp,
                isMine = message.isMine
            )
        }
    }
}

data class ChatMessageUi(
    val id: String,
    val text: String,
    val timestamp: String,
    val isMine: Boolean
)

@Preview(showBackground = true)
@Composable
fun ChatScreenPreview() {
    val messages = remember {
        mutableStateListOf(
            ChatMessageUi(
                id = "1",
                text = "Hey, how are you?",
                timestamp = "10:00",
                isMine = false
            ),
            ChatMessageUi(
                id = "2",
                text = "I'm good. Working on the chat screen.",
                timestamp = "10:01",
                isMine = true
            ),
            ChatMessageUi(
                id = "3",
                text = "Nice, it is starting to look good.",
                timestamp = "10:02",
                isMine = false
            )
        )
    }

    ChatScreen(
        username = "John Doe",
        messages = messages,
        onSendMessage = { text ->
            messages.add(
                ChatMessageUi(
                    id = System.currentTimeMillis().toString(),
                    text = text,
                    timestamp = "Now",
                    isMine = true
                )
            )
        }
    )
}