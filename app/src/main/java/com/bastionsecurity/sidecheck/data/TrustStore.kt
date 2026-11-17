package com.bastionsecurity.sidecheck.data

import android.content.Context
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.stringSetPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.map

private val Context.trustDataStore by preferencesDataStore(name = "trust")

/**
 * Remembers the user's "Keep" choices. Every key includes the signing certificate, so if an app is
 * replaced by one signed by someone else, the old choice no longer applies and we ask again.
 */
class TrustStore(private val context: Context) {

    private val trustedKey = stringSetPreferencesKey("trusted_apps")
    private val keptKey = stringSetPreferencesKey("kept_findings")

    data class Snapshot(val trustedApps: Set<String>, val keptFindings: Set<String>) {
        fun isTrusted(pkg: String, cert: String?) = appKey(pkg, cert) in trustedApps
        fun isKept(pkg: String, cert: String?, findingId: String) = findingKey(pkg, cert, findingId) in keptFindings
    }

    val snapshot: Flow<Snapshot> = context.trustDataStore.data.map {
        Snapshot(it[trustedKey].orEmpty(), it[keptKey].orEmpty())
    }

    suspend fun setTrusted(pkg: String, cert: String?, trusted: Boolean) = edit(trustedKey, appKey(pkg, cert), trusted)

    suspend fun setKept(pkg: String, cert: String?, findingId: String, kept: Boolean) =
        edit(keptKey, findingKey(pkg, cert, findingId), kept)

    /** Called after an app is uninstalled so nothing stale is left behind. */
    suspend fun forget(pkg: String) {
        context.trustDataStore.edit { prefs ->
            prefs[trustedKey] = prefs[trustedKey].orEmpty().filterNot { it.startsWith("$pkg|") }.toSet()
            prefs[keptKey] = prefs[keptKey].orEmpty().filterNot { it.startsWith("$pkg|") }.toSet()
        }
    }

    private suspend fun edit(key: androidx.datastore.preferences.core.Preferences.Key<Set<String>>, value: String, add: Boolean) {
        context.trustDataStore.edit { prefs ->
            val cur = prefs[key].orEmpty()
            prefs[key] = if (add) cur + value else cur - value
        }
    }

    companion object {
        fun appKey(pkg: String, cert: String?) = "$pkg|${cert ?: "unsigned"}"
        fun findingKey(pkg: String, cert: String?, id: String) = "${appKey(pkg, cert)}|$id"
    }
}
