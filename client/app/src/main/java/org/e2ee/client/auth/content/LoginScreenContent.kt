package org.e2ee.client.auth.content

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Person
import androidx.compose.material3.Icon
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment.Companion.CenterHorizontally
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import org.e2ee.client.R
import org.e2ee.client.ui.elements.AppButton
import org.e2ee.client.ui.elements.AppTextField
import org.e2ee.client.ui.elements.PasswordTextField

@Composable
fun LoginScreenContent(
    emailOrUsername: String,
    password: String,
    isLoading: Boolean,
    errorMessage: String?,
    onEmailOrUsernameChange: (String) -> Unit,
    onPasswordChange: (String) -> Unit,
    onLoginClick: () -> Unit,
) {

    Column(
        verticalArrangement = Arrangement.spacedBy(16.dp),
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp)
    ) {
        AppTextField(
            value = emailOrUsername,
            onValueChange = onEmailOrUsernameChange,
            placeholder = stringResource(R.string.email_or_username_placeholder),
            leadingIcon = {
                Icon(
                    imageVector = Icons.Default.Person,
                    contentDescription = null
                )
            }
        )

        PasswordTextField(
            value = password,
            onValueChange = onPasswordChange
        )

        errorMessage?.let {
            Text(text = it)
        }

        AppButton(
            onClick = onLoginClick,
            buttonText = if (isLoading) "Logging in..." else stringResource(R.string.login_button),
            modifier = Modifier
                .width(200.dp)
                .align(CenterHorizontally)
        ) { }
    }
}