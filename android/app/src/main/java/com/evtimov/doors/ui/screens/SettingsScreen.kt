package com.evtimov.doors.ui.screens

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import com.evtimov.doors.BuildConfig
import com.evtimov.doors.R
import com.evtimov.doors.di.ServiceLocator
import kotlinx.coroutines.launch

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SettingsScreen(onBack: () -> Unit, onForgotten: () -> Unit) {
    val scope = rememberCoroutineScope()
    val settings = ServiceLocator.settingsStore
    val haptics by settings.hapticsEnabled.collectAsState(initial = true)
    var confirming by remember { mutableStateOf(false) }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.settings_title)) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = null)
                    }
                },
            )
        },
    ) { padding ->
        Column(
            Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(16.dp),
        ) {
            Row(
                Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Text("Vibrate when a door opens", style = MaterialTheme.typography.bodyLarge)
                Switch(
                    checked = haptics,
                    onCheckedChange = { scope.launch { settings.setHaptics(it) } },
                )
            }

            Spacer(Modifier.height(24.dp))
            HorizontalDivider()
            Spacer(Modifier.height(24.dp))

            Text("This device", style = MaterialTheme.typography.titleMedium)
            Spacer(Modifier.height(8.dp))
            Text(
                "Device id: ${ServiceLocator.tokenStore.deviceId ?: "not enrolled"}",
                style = MaterialTheme.typography.bodySmall,
            )
            Text("App version: ${BuildConfig.VERSION_NAME}", style = MaterialTheme.typography.bodySmall)
            Text("Server: ${BuildConfig.API_HOST}", style = MaterialTheme.typography.bodySmall)

            Spacer(Modifier.height(24.dp))

            OutlinedButton(
                onClick = { scope.launch { ServiceLocator.repository.signOut() } },
                modifier = Modifier.fillMaxWidth(),
            ) {
                Text("Sign out")
            }

            Spacer(Modifier.height(8.dp))

            OutlinedButton(
                onClick = { confirming = true },
                modifier = Modifier.fillMaxWidth(),
            ) {
                Text("Remove this phone")
            }

            Spacer(Modifier.height(16.dp))
            Text(
                "Removing the phone deletes the key in secure hardware. It " +
                    "cannot be undone and this phone will need a new enrolment " +
                    "code. Tell your administrator so the old device row can be " +
                    "blocked as well.",
                style = MaterialTheme.typography.bodySmall,
            )
        }
    }

    if (confirming) {
        AlertDialog(
            onDismissRequest = { confirming = false },
            title = { Text("Remove this phone?") },
            text = {
                Text(
                    "The key in secure hardware is deleted and the session ends. " +
                        "You will need a new enrolment code to use this phone again."
                )
            },
            confirmButton = {
                TextButton(onClick = {
                    confirming = false
                    scope.launch {
                        ServiceLocator.repository.forgetThisDevice()
                        onForgotten()
                    }
                }) { Text("Remove") }
            },
            dismissButton = {
                TextButton(onClick = { confirming = false }) { Text("Cancel") }
            },
        )
    }
}
