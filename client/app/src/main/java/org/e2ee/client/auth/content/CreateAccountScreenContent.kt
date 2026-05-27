package org.e2ee.client.auth.content

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
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
fun CreateAccountScreenContent(
    email: String,
    username: String,
    password : String,
    confirmPassword : String,
    isLoading : Boolean,
    errorMessage: String?,
    onEmailChange : (String) -> Unit,
    onUsernameChange : (String) -> Unit,
    onPasswordChange : (String) -> Unit,
    onConfirmPasswordChange : (String) -> Unit,
    onCreateAccountClick : () -> Unit,
) {
    Column(
        verticalArrangement = Arrangement.spacedBy(16.dp),
        modifier = Modifier
            .padding(16.dp)
            .fillMaxSize()
    ) {
        AppTextField(
            value = email,
            onValueChange = onEmailChange,
            placeholder = stringResource(R.string.email_placeholder),
            leadingIcon = {
                Icon(
                    imageVector = Icons.Default.Person,
                    contentDescription = null
                )
            }
        )
        AppTextField(
            value = username,
            onValueChange = onUsernameChange,
            placeholder = stringResource(R.string.username_placeholder),
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

        PasswordTextField(
            value = confirmPassword,
            onValueChange = onConfirmPasswordChange
        )


        errorMessage?.let {
            Text(text = it)
        }

        AppButton(
            onClick = onCreateAccountClick,
            buttonText = if (isLoading) "Creating account..." else stringResource(R.string.create_account_button),
            modifier = Modifier
                .width(200.dp)
                .align(CenterHorizontally)
        ) { }

    }
}