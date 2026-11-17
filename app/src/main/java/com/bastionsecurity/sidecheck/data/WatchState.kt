package com.bastionsecurity.sidecheck.data

import android.content.Context
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.intPreferencesKey
import androidx.datastore.preferences.core.longPreferencesKey
import androidx.datastore.preferences.core.stringSetPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import com.bastionsecurity.sidecheck.engine.model.Grade
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.map

private val Context.watchDataStore by preferencesDataStore(name = "watch")

/** One app that was installed or updated since the user last looked. */
data class RecentChange(val packageName: String, val timeMillis: Long, val isNewInstall: Boolean, val grade: Grade? = null)

/** The grade and signer we last saw for an app, so updates are only flagged when they matter. */
data class KnownGrade(val grade: Grade, val cert: String)

/**
 * Bookkeeping for background protection: where we are in Android's package-change log, what we
 * last saw for each app, and what's new for the Home screen.
 */
class WatchState(private val context: Context) {
    private val seqKey = intPreferencesKey("sequence_number")
    private val bootKey = intPreferencesKey("boot_count")
    private val lastCheckKey = longPreferencesKey("last_check_time")
    private val gradesKey = stringSetPreferencesKey("known_grades") // pkg|grade|cert
    private val recentKey = stringSetPreferencesKey("recent_changes") // pkg|time|new|grade

    data class Cursor(val sequence: Int, val bootCount: Int, val lastCheckTime: Long)

    suspend fun cursor(): Cursor = context.watchDataStore.data.first().let {
        Cursor(it[seqKey] ?: 0, it[bootKey] ?: -1, it[lastCheckKey] ?: 0L)
    }

    suspend fun saveCursor(c: Cursor) {
        context.watchDataStore.edit {
            it[seqKey] = c.sequence
            it[bootKey] = c.bootCount
            it[lastCheckKey] = c.lastCheckTime
        }
    }

    suspend fun knownGrades(): Map<String, KnownGrade> =
        context.watchDataStore.data.first()[gradesKey].orEmpty().mapNotNull { row ->
            val p = row.split('|')
            if (p.size != 3) return@mapNotNull null
            val g = runCatching { Grade.valueOf(p[1]) }.getOrNull() ?: return@mapNotNull null
            p[0] to KnownGrade(g, p[2])
        }.toMap()

    suspend fun rememberGrades(grades: Map<String, KnownGrade>) {
        if (grades.isEmpty()) return
        context.watchDataStore.edit { prefs ->
            val kept = prefs[gradesKey].orEmpty().filterNot { it.substringBefore('|') in grades.keys }
            prefs[gradesKey] = (kept + grades.map { (pkg, k) -> "$pkg|${k.grade.name}|${k.cert}" }).toSet()
        }
    }

    val recent: Flow<List<RecentChange>> = context.watchDataStore.data.map { prefs ->
        val cutoff = System.currentTimeMillis() - RECENT_DAYS * 24L * 3600 * 1000
        prefs[recentKey].orEmpty().mapNotNull { row ->
            val p = row.split('|')
            if (p.size < 3) null else RecentChange(
                p[0], p[1].toLongOrNull() ?: 0L, p[2] == "new",
                p.getOrNull(3)?.let { g -> runCatching { Grade.valueOf(g) }.getOrNull() },
            )
        }.filter { it.timeMillis >= cutoff }.sortedByDescending { it.timeMillis }
    }

    suspend fun addRecent(changes: List<RecentChange>) {
        if (changes.isEmpty()) return
        context.watchDataStore.edit { prefs ->
            val pkgs = changes.map { it.packageName }.toSet()
            val kept = prefs[recentKey].orEmpty().filterNot { it.substringBefore('|') in pkgs }
            prefs[recentKey] = (kept + changes.map { "${it.packageName}|${it.timeMillis}|${if (it.isNewInstall) "new" else "upd"}|${it.grade?.name ?: ""}" })
                .takeLast(MAX_RECENT).toSet()
        }
    }

    /** The user has looked at this app (or removed it): drop it from "New since you last looked". */
    suspend fun acknowledge(pkg: String) {
        context.watchDataStore.edit { prefs ->
            prefs[recentKey] = prefs[recentKey].orEmpty().filterNot { it.substringBefore('|') == pkg }.toSet()
        }
    }

    companion object {
        private const val RECENT_DAYS = 7
        private const val MAX_RECENT = 30
    }
}
