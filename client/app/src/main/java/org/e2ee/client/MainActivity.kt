package org.e2ee.client

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.core.splashscreen.SplashScreen.Companion.installSplashScreen
import dagger.hilt.android.AndroidEntryPoint
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import org.e2ee.client.ui.theme.ClientTheme
import org.e2ee.domain.DatabasePrewarmer
import javax.inject.Inject

@AndroidEntryPoint
class MainActivity : ComponentActivity() {

    // Inject a lightweight prewarmer interface so this module does not need
    // direct access to Room/ClientDatabase on the compile classpath.
    @Inject lateinit var databasePrewarmer: DatabasePrewarmer

    // Tracks whether the pre-warm is still running.
    // The splash screen stays visible until this flips to true.
    private var dbReady = false

    override fun onCreate(savedInstanceState: Bundle?) {
        // Install splash screen BEFORE super.onCreate so it covers the
        // white flash while Hilt completes injection and the DB warms up.
        val splashScreen = installSplashScreen()

        super.onCreate(savedInstanceState)
        enableEdgeToEdge()

        // Keep the splash screen on screen until the database is open.
        // This moves the "frozen white screen" jank behind the branded splash.
        splashScreen.setKeepOnScreenCondition { !dbReady }

        // Pre-warm the SQLCipher database on the IO dispatcher so the first
        // DAO call from a ViewModel doesn't block the main thread.
        CoroutineScope(Dispatchers.IO + SupervisorJob()).launch {
            // Request the data module to pre-warm the DB. The implementation
            // lives in the :data module so it can reference Room safely.
            try {
                databasePrewarmer.preWarm()
            } catch (_: Throwable) {
                // Ignore any errors during pre-warm
            }
            dbReady = true
        }

        setContent {
            ClientTheme {
                App()
            }
        }
    }
}