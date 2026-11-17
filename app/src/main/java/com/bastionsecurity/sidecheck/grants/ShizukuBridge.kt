package com.bastionsecurity.sidecheck.grants

import android.content.Context
import android.content.pm.PackageManager
import android.util.Log
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.withContext
import rikka.shizuku.Shizuku
import java.util.concurrent.TimeUnit

/**
 * Optional "power user" mode. Shizuku is a separate free app that, once started over ADB or
 * wireless debugging, lets approved apps run commands with ADB-shell rights. With it, SideCheck can
 * turn other apps' permissions on/off directly. Without it, we send the user to Android Settings.
 *
 * Commands are passed as argument arrays (no shell), and every package/permission name is validated.
 */
class ShizukuBridge(private val context: Context) {

    enum class Status {
        /** Shizuku app isn't installed. */
        NOT_INSTALLED,
        /** Installed, but its service isn't running (needs to be started after each reboot). */
        NOT_RUNNING,
        /** Running, but SideCheck hasn't been allowed to use it yet. */
        NEEDS_PERMISSION,
        READY,
    }

    private val _status = MutableStateFlow(Status.NOT_INSTALLED)
    val status: StateFlow<Status> = _status.asStateFlow()

    private val binderReceived = Shizuku.OnBinderReceivedListener { refresh() }
    private val binderDead = Shizuku.OnBinderDeadListener { refresh() }
    private val permissionResult = Shizuku.OnRequestPermissionResultListener { _, _ -> refresh() }

    fun start() {
        Shizuku.addBinderReceivedListenerSticky(binderReceived)
        Shizuku.addBinderDeadListener(binderDead)
        Shizuku.addRequestPermissionResultListener(permissionResult)
        refresh()
    }

    fun refresh() {
        _status.value = try {
            when {
                !isInstalled() -> Status.NOT_INSTALLED
                !Shizuku.pingBinder() || Shizuku.isPreV11() -> Status.NOT_RUNNING
                Shizuku.checkSelfPermission() != PackageManager.PERMISSION_GRANTED -> Status.NEEDS_PERMISSION
                else -> Status.READY
            }
        } catch (e: Exception) {
            Log.w(TAG, "Shizuku status check failed", e)
            if (isInstalled()) Status.NOT_RUNNING else Status.NOT_INSTALLED
        }
    }

    fun requestPermission() {
        try {
            if (Shizuku.pingBinder()) Shizuku.requestPermission(REQUEST_CODE)
        } catch (e: Exception) {
            Log.w(TAG, "Shizuku permission request failed", e)
        }
    }

    private fun isInstalled(): Boolean = try {
        context.packageManager.getPackageInfo(SHIZUKU_PACKAGE, 0)
        true
    } catch (_: PackageManager.NameNotFoundException) {
        false
    }

    data class CommandResult(val exitCode: Int, val output: String) {
        val ok get() = exitCode == 0
    }

    suspend fun grantRuntime(pkg: String, permission: String, grant: Boolean) =
        run("pm", if (grant) "grant" else "revoke", checkName(pkg), checkName(permission))

    /** [op] is an app-op name such as SYSTEM_ALERT_WINDOW. */
    suspend fun setAppOp(pkg: String, op: String, allow: Boolean) =
        run("appops", "set", checkName(pkg), checkName(op), if (allow) "allow" else "ignore")

    /** Returns "allow", "ignore", "deny", "default", or null if it couldn't be read. */
    suspend fun getAppOp(pkg: String, op: String): String? {
        val r = run("appops", "get", checkName(pkg), checkName(op))
        if (!r.ok) return null
        if (r.output.contains("No operations", ignoreCase = true)) return "default"
        // e.g. "SYSTEM_ALERT_WINDOW: allow; time=+3d1h ago"
        return Regex("$op:\\s*(\\w+)").find(r.output)?.groupValues?.get(1)
    }

    private suspend fun run(vararg cmd: String): CommandResult = withContext(Dispatchers.IO) {
        if (_status.value != Status.READY) return@withContext CommandResult(-1, "Shizuku is not ready")
        try {
            // Shizuku 13 made newProcess private; reflection is the documented workaround for
            // simple commands. (A full UserService would be overkill for pm/appops calls.)
            val m = Shizuku::class.java.getDeclaredMethod(
                "newProcess", Array<String>::class.java, Array<String>::class.java, String::class.java,
            )
            m.isAccessible = true
            val p = m.invoke(null, arrayOf(*cmd), null, null) as Process
            val out = p.inputStream.bufferedReader().readText() + p.errorStream.bufferedReader().readText()
            val finished = p.waitFor(10, TimeUnit.SECONDS)
            if (!finished) {
                p.destroy()
                CommandResult(-1, "Timed out")
            } else {
                CommandResult(p.exitValue(), out.trim())
            }
        } catch (e: Exception) {
            Log.w(TAG, "Shizuku command failed: ${cmd.joinToString(" ")}", e)
            CommandResult(-1, e.cause?.message ?: e.message ?: "Failed")
        }
    }

    private fun checkName(s: String): String {
        require(NAME.matches(s)) { "Refusing unexpected name: $s" }
        return s
    }

    companion object {
        private const val TAG = "SideCheck"
        const val SHIZUKU_PACKAGE = "moe.shizuku.privileged.api"
        private const val REQUEST_CODE = 4242
        private val NAME = Regex("^[A-Za-z0-9_.]{1,200}$")
    }
}
