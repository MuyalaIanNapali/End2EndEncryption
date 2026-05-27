package org.e2ee.client.main.screen

import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding

import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import org.e2ee.client.ui.elements.AppTextField

@Composable
fun SearchScreen(
    modifier: Modifier = Modifier,
    query: String = "",
    onQueryChange: (String) -> Unit = {}
) {
    Box(
        modifier = modifier
            .fillMaxSize()
            .padding(16.dp)
    ) {
        AppTextField(
            value = query,
            onValueChange = onQueryChange,
            placeholder = "Search..."
        )
    }
}