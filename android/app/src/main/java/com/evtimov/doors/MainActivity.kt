package com.evtimov.doors

import android.os.Bundle
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.fragment.app.FragmentActivity
import com.evtimov.doors.ui.AppNavigation
import com.evtimov.doors.ui.theme.EvtimovDoorsTheme

/**
 * FragmentActivity rather than ComponentActivity because BiometricPrompt
 * needs a fragment manager. Everything above this line is Compose.
 */
class MainActivity : FragmentActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContent {
            EvtimovDoorsTheme {
                AppNavigation(activity = this)
            }
        }
    }
}
