package com.aethershield.app

import android.app.Application

/**
 * Deliberately minimal. No analytics SDK init, no crash reporter init, no
 * WorkManager scheduling of anything that phones home -- there is nothing to
 * initialize here beyond what Android requires by default.
 */
class AetherShieldApp : Application()
