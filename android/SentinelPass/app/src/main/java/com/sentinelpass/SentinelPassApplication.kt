package com.sentinelpass

import android.app.Application
import android.app.Application.ActivityLifecycleCallbacks
import android.os.Bundle
import androidx.lifecycle.ProcessLifecycleOwner
import androidx.lifecycle.lifecycle
import com.sentinelpass.data.VaultState

/**
 * SentinelPass Application class
 * Initializes app-wide state and lifecycle observers
 */
class SentinelPassApplication : Application() {

    override fun onCreate() {
        super.onCreate()

        // Initialize vault state
        VaultState.initialize(this)

        // Set up app background/foreground detection
        ProcessLifecycleOwner.get().lifecycle.addObserver(AppLifecycleObserver())
    }

    /**
     * Lifecycle observer for detecting app background/foreground
     * Used for auto-lock functionality
     */
    class AppLifecycleObserver : androidx.lifecycle.DefaultLifecycleObserver {
        private var wasInBackground = false

        override fun onStart(owner: androidx.lifecycle.LifecycleOwner) {
            if (wasInBackground) {
                // App returning from background - check if vault should be locked
                VaultState.checkAutoLock()
                wasInBackground = false
            }
        }

        override fun onStop(owner: androidx.lifecycle.LifecycleOwner) {
            wasInBackground = true
            // Note: Lock timer starts in onStop, actual lock check in onStart
            VaultState.scheduleAutoLock()
        }
    }
}
