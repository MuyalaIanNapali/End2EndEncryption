package org.e2ee.client.main.screen

import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.ui.Modifier
import androidx.hilt.lifecycle.viewmodel.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import org.e2ee.client.main.content.ScrollContent
import org.e2ee.client.main.viewmodel.ChatScreenViewModel
import org.e2ee.client.ui.elements.AppLoadingIndicator
import org.e2ee.client.ui.elements.ChatBottomBar
import org.e2ee.client.ui.elements.ChatTopAppBar

@Composable
fun ChatScreen(
    modifier: Modifier = Modifier,
    viewModel: ChatScreenViewModel = hiltViewModel(),
    sessionId: String,
    username: String,
    onBackClick: () -> Unit = {},
    onSettingsClick: () -> Unit = {}
) {
    val uiState = viewModel.uiState.collectAsStateWithLifecycle().value

    LaunchedEffect(sessionId) {
        viewModel.loadMessages(sessionId)
    }

    Scaffold(
        modifier = modifier.fillMaxSize(),
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
                    viewModel.sendMessage(
                        sessionId = sessionId,
                        messageText = message
                    )
                },
                onTyping = {
                    // Later: update typing status
                }
            )
        },
        contentWindowInsets = WindowInsets(0, 0, 0, 0)
    ) { innerPadding ->
        when {
            uiState.isLoading -> {
                AppLoadingIndicator()
            }

            uiState.errorMessage != null -> {
                Text(
                    text = uiState.errorMessage,
                    modifier = Modifier.padding(innerPadding)
                )
            }

            else -> {
                ScrollContent(
                    innerPadding = innerPadding,
                    messages = uiState.messages
                )
            }
        }
    }
}


