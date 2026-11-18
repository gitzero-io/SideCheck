package com.bastionsecurity.sidecheck.engine.rules

import com.bastionsecurity.sidecheck.engine.model.Finding

class RuleEngine(private val ruleSet: RuleSet) {

    /** Rules that reference a signal this build doesn't know. Exposed so the app can log them. */
    val unsupportedRules: List<String> = ruleSet.rules.filter { r ->
        (r.`when`.all + r.`when`.any + r.`when`.none).any { it !in Signals.registry }
    }.map { it.id }

    fun evaluate(ctx: RuleContext): List<Finding> {
        val cache = HashMap<String, SignalHit?>()
        fun signal(name: String): SignalHit? = cache.getOrPut(name) { Signals.registry[name]?.invoke(ctx) }

        val baseParams = mapOf(
            "app" to ctx.facts.label.ifBlank { ctx.facts.packageName },
            "targetSdk" to ctx.facts.targetSdk.toString(),
            "androidVersion" to Signals.androidVersion(ctx.facts.targetSdk),
        )

        val findings = mutableListOf<Finding>()
        for (baseRule in ruleSet.rules) {
            val rule = baseRule.on(ctx.platform)
            if (!rule.enabled || rule.id in unsupportedRules) continue
            val w = rule.`when`

            val hits = mutableListOf<SignalHit>()
            var ok = true
            for (name in w.all) {
                val h = signal(name)
                if (h == null) { ok = false; break }
                hits += h
            }
            if (!ok) continue
            if (w.any.isNotEmpty()) {
                val anyHits = w.any.mapNotNull { signal(it) }
                if (anyHits.isEmpty()) continue
                hits += anyHits
            }
            if (w.none.any { signal(it) != null }) continue
            if (w.anyPermission.isNotEmpty()) {
                val perms = w.anyPermission.filter { ctx.facts.hasPermission(it) }
                if (perms.isEmpty()) continue
                hits += SignalHit(
                    perms.map { "Permission: $it" },
                    mapOf("permissionList" to PermissionNames.describe(perms)),
                )
            }
            w.targetSdkBelow?.let { if (ctx.facts.targetSdk >= it) continue }
            w.targetSdkAtLeast?.let { if (ctx.facts.targetSdk < it) continue }
            if (w.targetSdkBelow != null || w.targetSdkAtLeast != null) {
                hits += SignalHit(listOf("targetSdkVersion=${ctx.facts.targetSdk}"))
            }
            // A rule with no conditions at all never fires.
            if (hits.isEmpty()) continue

            val params = HashMap(baseParams)
            hits.forEach { params.putAll(it.params) }
            findings += Finding(
                id = rule.id,
                severity = rule.severity,
                category = rule.category,
                plainTitle = fill(rule.title, params),
                plainExplanation = fill(rule.explanation, params),
                whyItMatters = fill(rule.why, params),
                technicalEvidence = hits.flatMap { it.evidence }.distinct(),
                suggestedAction = rule.action,
                isHeuristic = rule.heuristic,
                gradeCap = rule.gradeCap,
            )
        }

        // Mark findings whose points a combined finding already counts.
        val fired = findings.associateBy { it.id }
        val countedIn = HashMap<String, String>()
        for (rule in ruleSet.rules) {
            if (rule.id !in fired) continue
            for (sub in rule.supersedes) if (sub in fired && sub !in countedIn) countedIn[sub] = rule.id
        }
        return findings.map { f -> countedIn[f.id]?.let { f.copy(countedIn = it) } ?: f }
    }

    companion object {
        private val PLACEHOLDER = Regex("\\{(\\w+)\\}")

        fun fill(template: String, params: Map<String, String>): String =
            PLACEHOLDER.replace(template) { m -> params[m.groupValues[1]] ?: m.value }
    }
}
