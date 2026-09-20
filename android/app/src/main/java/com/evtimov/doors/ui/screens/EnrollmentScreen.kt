package com.evtimov.doors.ui.screens

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.unit.dp
import com.evtimov.doors.R
import com.evtimov.doors.di.ServiceLocator
import com.evtimov.doors.ui.components.MessageCard
import com.evtimov.doors.ui.components.Tone
import androidx.compose.ui.res.stringResource
import kotlinx.coroutines.launch

@Composable
fun EnrollmentScreen(onEnrolled: () -> Unit) {
    var code by remember { mutableStateOf("") }
    var label by remember { mutableStateOf(android.os.Build.MODEL ?: "My phone") }
    var busy by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }
    val scope = rememberCoroutineScope()

    Scaffold { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(24.dp),
            verticalArrangement = Arrangement.Center,
        ) {
            Text(
                stringResource(R.string.enroll_title),
                style = MaterialTheme.typography.displaySmall,
            )
            Spacer(Modifier.height(8.dp))
            Text(
                stringResource(R.string.enroll_subtitle),
                style = MaterialTheme.typography.bodyLarge,
            )
            Spacer(Modifier.height(32.dp))

            OutlinedTextField(
                value = code,
                onValueChange = { code = it.trim() },
                label = { Text(stringResource(R.string.enroll_code_label)) },
                singleLine = true,
                enabled = !busy,
                modifier = Modifier.fillMaxWidth(),
            )
            Spacer(Modifier.height(16.dp))
            OutlinedTextField(
                value = label,
                onValueChange = { label = it },
                label = { Text(stringResource(R.string.enroll_device_label)) },
                singleLine = true,
                enabled = !busy,
                keyboardOptions = androidx.compose.foundation.text.KeyboardOptions(
                    imeAction = ImeAction.Done,
                ),
                modifier = Modifier.fillMaxWidth(),
            )

            Spacer(Modifier.height(24.dp))

            Button(
                onClick = {
                    busy = true
                    error = null
                    scope.launch {
                        val result = ServiceLocator.repository.enroll(code, label)
                        busy = false
                        result.fold(
                            onSuccess = { onEnrolled() },
                            onFailure = {
                                // Deliberately vague. The server does not say
                                // whether the code was wrong, already used or
                                // simply expired, and neither does the app.
                                error = "Enrolment failed. Check the code with " +
                                    "your administrator and try again."
                            },
                        )
                    }
                },
                enabled = !busy && code.length >= 8 && label.isNotBlank(),
                modifier = Modifier.fillMaxWidth(),
            ) {
                if (busy) {
                    CircularProgressIndicator(Modifier.height(20.dp), strokeWidth = 2.dp)
                } else {
                    Text(stringResource(R.string.enroll_action))
                }
            }

            error?.let {
                Spacer(Modifier.height(16.dp))
                MessageCard("Could not enrol", it, Tone.Error)
            }

            Spacer(Modifier.height(24.dp))
            Text(
                "This creates a key inside your phone's secure hardware. It " +
                    "cannot be copied to another device, and it will not work " +
                    "without your fingerprint or face.",
                style = MaterialTheme.typography.bodySmall,
            )
        }
    }
}
