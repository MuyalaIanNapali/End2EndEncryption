package org.e2ee.client.main.screen

import android.annotation.SuppressLint
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.Message
import androidx.compose.material3.FloatingActionButton
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableFloatStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.input.nestedscroll.NestedScrollConnection
import androidx.compose.ui.input.nestedscroll.NestedScrollSource
import androidx.compose.ui.input.nestedscroll.nestedScroll
import androidx.compose.ui.platform.LocalConfiguration
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.hilt.lifecycle.viewmodel.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import org.e2ee.client.R
import org.e2ee.client.main.viewmodel.MessagesScreenViewModel
import org.e2ee.client.ui.elements.MainTopAppBar
import org.e2ee.client.ui.elements.MessageCard

@SuppressLint("ConfigurationScreenWidthHeight")
@Composable
fun MessagesScreen(
    modifier: Modifier = Modifier,
    viewModel: MessagesScreenViewModel = hiltViewModel(),
    onLogoutClick: () -> Unit = {},
    onFabClick: () -> Unit = {},
    onSettingsClick: () -> Unit = {},
    onChatCardClick: (sessionId: String, contactId: String, contactName: String, contactEmail: String) -> Unit = { _, _, _, _ -> }
) {
    val uiState = viewModel.uiState.collectAsStateWithLifecycle().value

    LaunchedEffect(Unit) {
        viewModel.loadChatPreviews()
    }

    val configuration = LocalConfiguration.current
    val density = LocalDensity.current

    val expandedHeight = configuration.screenHeightDp.dp / 2
    val collapsedHeight = 82.dp

    val expandedHeightPx = with(density) { expandedHeight.toPx() }
    val collapsedHeightPx = with(density) { collapsedHeight.toPx() }

    val maxOffset = expandedHeightPx - collapsedHeightPx

    var headerOffsetPx by remember { mutableFloatStateOf(0f) }

    val currentHeaderHeightPx = expandedHeightPx - headerOffsetPx
    val currentHeaderHeightDp = with(density) { currentHeaderHeightPx.toDp() }

    val collapseProgress = if (maxOffset == 0f) 0f else headerOffsetPx / maxOffset

    val nestedScrollConnection = remember {
        object : NestedScrollConnection {
            override fun onPreScroll(available: Offset, source: NestedScrollSource): Offset {
                val delta = available.y
                val newOffset = headerOffsetPx - delta
                headerOffsetPx = newOffset.coerceIn(0f, maxOffset)
                return Offset.Zero
            }
        }
    }

    Box(
        modifier = modifier
            .fillMaxSize()
            .background(MaterialTheme.colorScheme.background)
            .nestedScroll(nestedScrollConnection)
    ) {
        LazyColumn(
            modifier = Modifier.fillMaxSize(),
            contentPadding = PaddingValues(
                top = currentHeaderHeightDp + 16.dp,
                start = 16.dp,
                end = 16.dp,
                // Extra bottom padding so the last item is never hidden behind the FAB + nav bar
                bottom = 96.dp
            ),
            verticalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            items(
                items = uiState.chatCards,
                key = { it.sessionId }
            ) { chat ->
                MessageCard(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(horizontal = 4.dp),
                    otherUserName = chat.contactName,
                    lastMessage = chat.lastMessage,
                    timestamp = chat.timestamp,
                    unreadMessageCount = chat.unreadMessageCount,
                    onClick = {
                        viewModel.markChatAsRead(chat.sessionId)
                        onChatCardClick(
                            chat.sessionId,
                            chat.contactId.toString(),
                            chat.contactName,
                            chat.contactEmail
                        )
                    }
                )
            }
        }

        MainTopAppBar(
            title = stringResource(R.string.app_name),
            height = currentHeaderHeightDp,
            collapseProgress = collapseProgress,
            onLogOutClicked = onLogoutClick,
            onSettingsClicked = onSettingsClick
        )

        FloatingActionButton(
            onClick = onFabClick,
            modifier = Modifier
                .align(Alignment.BottomEnd)
                // navigationBarsPadding lifts FAB above on-screen navigation buttons;
                // the extra 16.dp gives breathing room above the nav bar
                .navigationBarsPadding()
                .padding(end = 24.dp, bottom = 16.dp)
        ) {
            Icon(
                imageVector = Icons.AutoMirrored.Filled.Message,
                contentDescription = stringResource(R.string.new_chat_content_description)
            )
        }
    }
}