package org.e2ee.client.navigation

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.padding
import androidx.compose.runtime.Composable
import androidx.compose.runtime.derivedStateOf
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import androidx.lifecycle.viewmodel.navigation3.rememberViewModelStoreNavEntryDecorator
import androidx.navigation3.runtime.entryProvider
import androidx.navigation3.runtime.rememberNavBackStack
import androidx.navigation3.runtime.rememberSaveableStateHolderNavEntryDecorator
import androidx.navigation3.ui.NavDisplay
import org.e2ee.client.auth.screen.ForgotPasswordScreen
import org.e2ee.client.auth.screen.RegisterScreen
import org.e2ee.client.auth.screen.LoginScreen
import org.e2ee.client.ui.elements.AuthScreenShell


@Composable
fun AuthNavigation(
    modifier: Modifier = Modifier
) {
    val authBackStack = rememberNavBackStack(Route.Auth.Login)

    val currentRoute = remember {
        derivedStateOf {
            authBackStack.lastOrNull()
        }
    }

    AuthScreenShell(
        modifier = modifier,
        selectedRoute = currentRoute.value as Route.Auth?,
        onLoginClick = {
            authBackStack.clear()
            authBackStack.add(Route.Auth.Login)
        },
        onRegisterClick = {
            authBackStack.clear()
            authBackStack.add(Route.Auth.Register)
        },
        showToggle = currentRoute.value != Route.Auth.ForgotPassword
    ) { contentModifier ->

        NavDisplay(
            modifier = contentModifier,
            backStack = authBackStack,
            entryDecorators = listOf(
                rememberSaveableStateHolderNavEntryDecorator(),
                rememberViewModelStoreNavEntryDecorator()
            ),
            entryProvider = entryProvider {
                entry<Route.Auth.Login> {
                    LoginScreen(
                        onRegisterClick = {
                            authBackStack.clear()
                            authBackStack.add(Route.Auth.Register)
                        },
                        onForgotPasswordClick = {
                            authBackStack.add(Route.Auth.ForgotPassword)
                        }
                    )
                }

                entry<Route.Auth.Register> {
                    RegisterScreen(
                        onLoginClick = {
                            authBackStack.clear()
                            authBackStack.add(Route.Auth.Login)
                        }
                    )
                }

                entry<Route.Auth.ForgotPassword> {
                    ForgotPasswordScreen(
                        onBackClick = {
                            authBackStack.removeLastOrNull()
                        }
                    )
                }
            }
        )
    }
}
/*
@Composable
fun LoginScreen(onRegisterClick: () -> add, onForgotPasswordClick: () -> add) {
    TODO("Not yet implemented")
}

 */

@Composable
@Preview
fun AuthNavigationPreview() {
    AuthNavigation(
        modifier = Modifier.padding(16.dp)
    )
}