package com.bsdm.connect

import android.content.Intent
import android.net.VpnService
import android.os.ParcelFileDescriptor
import android.util.Log

/**
 * Android VpnService Bridge for BSDM Connect
 * Handles Android VPN routing and integrates with WireGuard/Amnezia tunnel parameters.
 */
class BsdmVpnService : VpnService() {

    private var vpnInterface: ParcelFileDescriptor? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        Log.i(TAG, "Starting BSDM VPN Service")
        setupVpn()
        return START_STICKY
    }

    private fun setupVpn() {
        try {
            val builder = Builder()
                .setSession("BSDM Connect")
                .addAddress("10.8.0.2", 32)
                .addRoute("10.0.0.0", 8)
                .addDnsServer("10.8.0.1")
                .setMtu(1360)
                .setBlocking(true)

            vpnInterface = builder.establish()
            Log.i(TAG, "BSDM VPN Interface established successfully")
        } catch (e: Exception) {
            Log.e(TAG, "Error establishing VPN interface", e)
        }
    }

    override fun onDestroy() {
        super.onDestroy()
        vpnInterface?.close()
        vpnInterface = null
        Log.i(TAG, "BSDM VPN Service destroyed")
    }

    companion object {
        private const val TAG = "BsdmVpnService"
    }
}
