package com.evtimov.doors

import android.app.Application
import com.evtimov.doors.di.ServiceLocator

class DoorsApplication : Application() {
    override fun onCreate() {
        super.onCreate()
        ServiceLocator.initialise(this)
    }
}
