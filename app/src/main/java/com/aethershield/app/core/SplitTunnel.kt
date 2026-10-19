package com.aethershield.app.core

/**
 * What can honestly be said about one app's route. Three outcomes only:
 *  - VIA_VPN: the app's traffic is captured by the tunnel;
 *  - DIRECT: the app connects on the normal network, outside the tunnel;
 *  - UNVERIFIABLE: it cannot be confirmed right now ([Reason] says why).
 * "Verified" here means: the rule is part of the VPN interface Android is running RIGHT NOW. It does not
 * mean the app cannot find another way around the VPN (see the limits text in the UI).
 */
enum class RouteStatus { VIA_VPN, DIRECT, UNVERIFIABLE }

enum class RouteReason { NONE, THIS_APP, PROXY_MODE, NOT_CONNECTED, PENDING_RECONNECT }

data class AppRouting(val mode: AppSelectionMode, val selected: Set<String>)

data class RouteView(val status: RouteStatus, val planned: RouteStatus, val reason: RouteReason)

object SplitTunnel {

    /** Where [pkg] goes according to a selection, ignoring whether a tunnel is up. Never UNVERIFIABLE. */
    fun planned(pkg: String, selfPackage: String, routing: AppRouting): RouteStatus = when {
        pkg == selfPackage -> RouteStatus.DIRECT // our own process is always kept out of its own tunnel
        routing.mode == AppSelectionMode.NONE -> RouteStatus.VIA_VPN
        routing.mode == AppSelectionMode.EXCLUDE_SELECTED ->
            if (pkg in routing.selected) RouteStatus.DIRECT else RouteStatus.VIA_VPN
        else -> if (pkg in routing.selected) RouteStatus.VIA_VPN else RouteStatus.DIRECT
    }

    /**
     * @param draft the selection as currently set in the app (what the user sees and may still change)
     * @param applied the selection the RUNNING VPN interface was built with, or null when no VPN is running
     */
    fun view(
        pkg: String,
        selfPackage: String,
        draft: AppRouting,
        connectionMode: ConnectionMode,
        applied: AppRouting?
    ): RouteView {
        val planned = planned(pkg, selfPackage, draft)
        if (pkg == selfPackage) return RouteView(RouteStatus.DIRECT, planned, RouteReason.THIS_APP)
        if (connectionMode == ConnectionMode.PROXY_ONLY) {
            // No OS-level capture at all: an app uses the proxy only if it is set up to.
            return RouteView(RouteStatus.UNVERIFIABLE, planned, RouteReason.PROXY_MODE)
        }
        if (applied == null) return RouteView(RouteStatus.UNVERIFIABLE, planned, RouteReason.NOT_CONNECTED)
        val inForce = planned(pkg, selfPackage, applied)
        if (inForce != planned) return RouteView(RouteStatus.UNVERIFIABLE, planned, RouteReason.PENDING_RECONNECT)
        return RouteView(inForce, planned, RouteReason.NONE)
    }
}
