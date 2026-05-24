package org.e2ee.client.ui.elements

import androidx.compose.foundation.layout.width
import androidx.compose.material3.Button
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.tooling.preview.PreviewLightDark
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp

@Composable
fun AppButton(
    modifier: Modifier = Modifier,
    onClick: () -> Unit,
    buttonText: String,
    content: @Composable () -> Unit
){
    FilledTonalButton(
        onClick = { onClick() },
        modifier = modifier
    ) {
        Text(buttonText)

    }

}

@Composable
@Preview
fun AppButtonPreview(){
    AppButton(
        onClick = {},
        buttonText = "Login",
        modifier = Modifier.width(200.dp)
    ) {

    }
}