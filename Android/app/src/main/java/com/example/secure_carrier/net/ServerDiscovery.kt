package com.example.secure_carrier.net

import android.util.Log
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket

object ServerDiscovery {
    private const val TAG = "ServerDiscovery"
    private const val PORT = 8080
    private const val TIMEOUT_MS = 2000
    private var cachedServerUrl: String? = null

    /**
     * Discovers the server by scanning the local subnet for an open port 8080.
     * Scans IPs on the same subnet as the device (e.g., 192.168.0.1 to 192.168.0.255).
     * Returns the first IP that responds, or null if none found.
     */
    fun discoverServer(): String? {
        // Return cached URL if available
        cachedServerUrl?.let {
            Log.d(TAG, "Using cached server URL: $it")
            return it
        }

        return try {
            // Get device's own IP to determine subnet
            val deviceIp = getDeviceIpAddress()
            if (deviceIp.isNullOrEmpty()) {
                Log.w(TAG, "Could not determine device IP")
                return null
            }
            Log.d(TAG, "Device IP: $deviceIp")

            // Extract subnet (e.g., "192.168.0" from "192.168.0.x")
            val subnet = deviceIp.substringBeforeLast(".")
            Log.d(TAG, "Scanning subnet: $subnet.0 - $subnet.255")

            // Scan subnet for open port 8080
            for (i in 1..254) {
                val ipToCheck = "$subnet.$i"
                if (isServerAvailable(ipToCheck)) {
                    val url = "http://$ipToCheck:$PORT"
                    Log.d(TAG, "Server found at: $url")
                    cachedServerUrl = url
                    return url
                }
            }

            Log.w(TAG, "No server found on subnet")
            null
        } catch (e: Exception) {
            Log.e(TAG, "Error discovering server", e)
            null
        }
    }

    /**
     * Check if server is available at the given IP.
     */
    private fun isServerAvailable(ip: String): Boolean {
        return try {
            val socket = Socket()
            socket.connect(InetSocketAddress(ip, PORT), TIMEOUT_MS)
            socket.close()
            Log.d(TAG, "Server responding at $ip:$PORT")
            true
        } catch (e: Exception) {
            false
        }
    }

    /**
     * Get the device's local IP address on the current network.
     */
    private fun getDeviceIpAddress(): String? {
        return try {
            val interfaces = java.net.NetworkInterface.getNetworkInterfaces()
            for (intf in interfaces) {
                for (addr in intf.inetAddresses) {
                    // Skip loopback and IPv6
                    val hostAddr = addr.hostAddress
                    if (!addr.isLoopbackAddress && hostAddr != null && hostAddr.contains(".")) {
                        Log.d(TAG, "Found local IP: $hostAddr")
                        return hostAddr
                    }
                }
            }
            null
        } catch (e: Exception) {
            Log.e(TAG, "Error getting device IP", e)
            null
        }
    }

    /**
     * Clear the cached server URL (useful for forcing a re-scan).
     */
    fun clearCache() {
        cachedServerUrl = null
        Log.d(TAG, "Cached server URL cleared")
    }
}
