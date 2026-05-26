package org.e2ee.client.main.screen

import android.annotation.SuppressLint
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableFloatStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.input.nestedscroll.NestedScrollConnection
import androidx.compose.ui.input.nestedscroll.NestedScrollSource
import androidx.compose.ui.input.nestedscroll.nestedScroll
import androidx.compose.ui.platform.LocalConfiguration
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import org.e2ee.client.R
import org.e2ee.client.ui.elements.MainTopAppBar
import org.e2ee.client.ui.elements.MessageCard

@SuppressLint("ConfigurationScreenWidthHeight")
@Composable
fun MessagesScreen(
    modifier: Modifier = Modifier,
    onSettingsClick: () -> Unit = {},
    onChatCardClick: (otherUserName: String) -> Unit = { _ -> }
) {
    val configuration = LocalConfiguration.current
    val density = LocalDensity.current

    val expandedHeight = configuration.screenHeightDp.dp / 2
    val collapsedHeight = 82.dp

    val expandedHeightPx = with(density) { expandedHeight.toPx() }
    val collapsedHeightPx = with(density) { collapsedHeight.toPx() }

    val maxOffset = expandedHeightPx - collapsedHeightPx

    var headerOffsetPx by remember {
        mutableFloatStateOf(0f)
    }

    val currentHeaderHeightPx = expandedHeightPx - headerOffsetPx

    val currentHeaderHeightDp = with(density) {
        currentHeaderHeightPx.toDp()
    }

    val collapseProgress = if (maxOffset == 0f) {
        0f
    } else {
        headerOffsetPx / maxOffset
    }

    val nestedScrollConnection = remember {
        object : NestedScrollConnection {
            override fun onPreScroll(
                available: Offset,
                source: NestedScrollSource
            ): Offset {
                val delta = available.y

                val newOffset = headerOffsetPx - delta
                headerOffsetPx = newOffset.coerceIn(0f, maxOffset)

                return Offset.Zero
            }
        }
    }

    val chats = listOf(
        ChatPreview(
            otherUserName = "Alice",
            lastMessage = "Hey, how are you?",
            timestamp = "10:30 AM",
            unreadMessageCount = 2
        ),
        ChatPreview(
            otherUserName = "Bob",
            lastMessage = "Let's catch up later.",
            timestamp = "9:15 AM",
            unreadMessageCount = 0
        ),
        ChatPreview(
            otherUserName = "Charlie",
            lastMessage = "Did you finish the encryption module?",
            timestamp = "Yesterday",
            unreadMessageCount = 4
        ),
        ChatPreview(
            otherUserName = "Diana",
            lastMessage = "Okay, noted.",
            timestamp = "Mon",
            unreadMessageCount = 0
        )
    )

    Box(
        modifier = modifier
            .fillMaxSize()
            .background(Color.White)
            .nestedScroll(nestedScrollConnection)
    ) {
        LazyColumn(
            modifier = Modifier.fillMaxSize(),
            contentPadding = PaddingValues(
                top = currentHeaderHeightDp + 16.dp,
                start = 16.dp,
                end = 16.dp,
                bottom = 16.dp
            ),
            verticalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            items(chats) { chat ->
                MessageCard(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(horizontal = 4.dp),
                    otherUserName = chat.otherUserName,
                    lastMessage = chat.lastMessage,
                    timestamp = chat.timestamp,
                    unreadMessageCount = chat.unreadMessageCount,
                    onClick = { onChatCardClick(chat.otherUserName) }
                )
            }

            items(20) { index ->
                MessageCard(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(horizontal = 4.dp),
                    otherUserName = "User ${index + 1}",
                    lastMessage = "This is a sample chat message",
                    timestamp = "12:${index.toString().padStart(2, '0')}",
                    unreadMessageCount = if (index % 3 == 0) index + 1 else 0
                )
            }
        }

        MainTopAppBar(
            title = stringResource(R.string.app_name),
            height = currentHeaderHeightDp,
            collapseProgress = collapseProgress,
            onSettingsClick = onSettingsClick
        )
    }
}

private data class ChatPreview(
    val otherUserName: String,
    val lastMessage: String,
    val timestamp: String,
    val unreadMessageCount: Int
)


@Composable
@Preview
fun ChatsScreenPreview() {
    MessagesScreen ()
}