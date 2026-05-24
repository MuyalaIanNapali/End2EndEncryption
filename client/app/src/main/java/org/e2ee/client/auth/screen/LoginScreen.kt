package org.e2ee.client.auth.screen

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Person
import androidx.compose.material3.Icon
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment.Companion.CenterHorizontally
import androidx.compose.ui.Modifier
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import org.e2ee.client.ui.elements.AppButton
import org.e2ee.client.ui.elements.AppTextField
import org.e2ee.client.ui.elements.PasswordTextField

@Composable
fun LoginScreen(
    onRegisterClick: () -> Unit,
    onForgotPasswordClick: () -> Unit
) {
    val email = remember { mutableStateOf("") }
    val password = remember { mutableStateOf("") }

    Column(
        verticalArrangement = Arrangement.spacedBy(16.dp),
        modifier = Modifier
            .padding(16.dp)
            .fillMaxSize()
    ) {
        AppTextField(
            value = email.value,
            onValueChange = { email.value = it },
            placeholder = "Email or username",
            leadingIcon = {
                Icon(
                    imageVector = Icons.Default.Person,
                    contentDescription = null
                )
            }
        )

        PasswordTextField(
            value = password.value,
            onValueChange = { password.value = it }
        )
        // Your login fields and button here

        TextButton(
            onClick = onForgotPasswordClick,
            modifier = Modifier.align(CenterHorizontally)
        ) {
            Text("Forgot Password?")
        }

        AppButton(
            onClick = { /* Handle login logic here */ },
            buttonText = "Login",
            modifier = Modifier
                .width(200.dp)
                .align (CenterHorizontally)
        ) { }



    }

}

@Preview
@Composable
fun LoginScreenPreview() {
    LoginScreen(
        onRegisterClick = {},
        onForgotPasswordClick = {}
    )
}