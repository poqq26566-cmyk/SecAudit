package com.test.secaudit

import android.app.AppOpsManager
import android.app.admin.DevicePolicyManager
import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.os.Build
import android.provider.Settings

/** Un motivo de sospecha con su peso para el score compuesto. */
data class Reason(val text: String, val weight: Int)

/** Resultado de riesgo de una app concreta (solo apps de usuario / no-sistema). */
data class AppRisk(
    val pkg: String,
    val label: String,
    val sideloaded: Boolean,
    val reasons: List<Reason>,
    val score: Int
) {
    /** ≥5 = riesgo ALTO; 3-4 = MEDIO (umbral de marcado). */
    val high: Boolean get() = score >= 5
}

/** Resultado global del escaneo, para el resumen y la pantalla de detalle. */
data class ScanResult(
    val flagged: List<AppRisk>,        // no-sistema, score >= 3, ordenadas desc
    val hidden: List<AppRisk>,         // no-sistema sin ícono
    val hiddenRisky: Boolean,          // alguna oculta es de origen no confiable
    val accessibility: List<String>,   // labels de servicios de accesibilidad no-sistema
    val notifListeners: List<String>,  // labels con acceso a notificaciones (no-sistema)
    val deviceAdmins: List<String>,    // labels admins de dispositivo (no-sistema)
    val sideloadedCount: Int,
    val totalUserApps: Int
)

/**
 * Escaneo del parque de apps con criterio compuesto, sin root. Pensado para correr en un
 * hilo de fondo. Se centra en apps **de usuario** (no-sistema). Los permisos sensibles
 * solo puntúan cuando el origen no es Google Play (combinación de señales), para no marcar
 * apps legítimas de la tienda (WhatsApp, etc.).
 */
object AppScanner {

    private val PLAY_STORES = setOf("com.android.vending", "com.google.android.feedback")

    fun scan(ctx: Context): ScanResult {
        val pm = ctx.packageManager
        val self = ctx.packageName
        val ops = ctx.getSystemService(Context.APP_OPS_SERVICE) as? AppOpsManager

        val accPkgs = enabledServicePkgs(ctx, Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES)
        val notifPkgs = enabledServicePkgs(ctx, "enabled_notification_listeners")
        val adminPkgs = deviceAdminPkgs(ctx)

        @Suppress("DEPRECATION")
        val pkgs: List<PackageInfo> = try {
            pm.getInstalledPackages(PackageManager.GET_PERMISSIONS)
        } catch (_: Exception) { emptyList() }

        val flagged = ArrayList<AppRisk>()
        val hidden = ArrayList<AppRisk>()
        var sideloadedCount = 0
        var userApps = 0
        val accLabels = ArrayList<String>()
        val notifLabels = ArrayList<String>()
        val adminLabels = ArrayList<String>()

        for (pi in pkgs) {
            val ai = pi.applicationInfo ?: continue
            val pkg = pi.packageName
            if (pkg == self) continue
            val isSystem = (ai.flags and (ApplicationInfo.FLAG_SYSTEM or ApplicationInfo.FLAG_UPDATED_SYSTEM_APP)) != 0
            val label = runCatching { ai.loadLabel(pm).toString() }.getOrDefault(pkg)

            // Labels para el resumen: servicios potentes en manos de apps NO-sistema.
            if (!isSystem && pkg in accPkgs) accLabels.add(label)
            if (!isSystem && pkg in notifPkgs) notifLabels.add(label)
            if (!isSystem && pkg in adminPkgs) adminLabels.add(label)

            // El análisis de "sospechosas/ocultas" se limita a apps de usuario.
            if (isSystem) continue
            userApps++

            val sideloaded = isSideloaded(pm, pkg)
            if (sideloaded) sideloadedCount++

            val reasons = ArrayList<Reason>()

            val hasLauncher = pm.getLaunchIntentForPackage(pkg) != null ||
                pm.getLeanbackLaunchIntentForPackage(pkg) != null
            val isHidden = !hasLauncher
            if (isHidden) reasons.add(Reason("Sin ícono en el cajón de apps (oculta)", 2))

            if (pkg in accPkgs) reasons.add(Reason("Servicio de accesibilidad activo: puede leer la pantalla y simular toques", 3))
            if (pkg in adminPkgs) reasons.add(Reason("Administrador de dispositivo: dificulta su desinstalación", 3))
            if (pkg in notifPkgs) reasons.add(Reason("Lee todas las notificaciones (incluye códigos 2FA)", 3))

            val granted = grantedPermissions(pi)
            val uid = ai.uid

            if ("android.permission.SYSTEM_ALERT_WINDOW" in granted &&
                appOpAllowed(ops, AppOpsManager.OPSTR_SYSTEM_ALERT_WINDOW, uid, pkg)
            ) reasons.add(Reason("Puede dibujar sobre otras apps (overlays)", 2))

            if ("android.permission.REQUEST_INSTALL_PACKAGES" in granted)
                reasons.add(Reason("Puede instalar otras apps", 2))

            if (appOpAllowed(ops, AppOpsManager.OPSTR_GET_USAGE_STATS, uid, pkg))
                reasons.add(Reason("Acceso a estadísticas de uso de apps", 1))

            if (ai.targetSdkVersion < Build.VERSION_CODES.M)
                reasons.add(Reason("Apunta a una API muy vieja (targetSdk ${ai.targetSdkVersion}): evade permisos modernos", 2))

            if ((ai.flags and ApplicationInfo.FLAG_DEBUGGABLE) != 0)
                reasons.add(Reason("Compilada en modo depuración", 1))

            if (sideloaded) reasons.add(Reason("Instalada fuera de Google Play", 1))

            // Permisos sensibles: solo puntúan si el origen NO es Play (señal compuesta).
            val danger = listOf(
                "android.permission.READ_SMS" to "leer SMS",
                "android.permission.SEND_SMS" to "enviar SMS",
                "android.permission.READ_CALL_LOG" to "registro de llamadas",
                "android.permission.RECORD_AUDIO" to "micrófono",
                "android.permission.CAMERA" to "cámara",
                "android.permission.READ_CONTACTS" to "contactos",
                "android.permission.ACCESS_BACKGROUND_LOCATION" to "ubicación en 2.º plano"
            ).filter { it.first in granted }
            if (danger.isNotEmpty() && sideloaded) {
                reasons.add(Reason(
                    "Permisos sensibles: " + danger.joinToString(", ") { it.second },
                    danger.size.coerceAtMost(3)
                ))
            }

            val score = reasons.sumOf { it.weight }
            val risk = AppRisk(pkg, label, sideloaded, reasons, score)
            if (isHidden) hidden.add(risk)
            if (score >= 3) flagged.add(risk)
        }

        flagged.sortByDescending { it.score }
        return ScanResult(
            flagged = flagged,
            hidden = hidden,
            hiddenRisky = hidden.any { it.sideloaded },
            accessibility = accLabels,
            notifListeners = notifLabels,
            deviceAdmins = adminLabels,
            sideloadedCount = sideloadedCount,
            totalUserApps = userApps
        )
    }

    // ----------------------------------------------------------------- helpers

    private fun grantedPermissions(pi: PackageInfo): Set<String> {
        val perms = pi.requestedPermissions ?: return emptySet()
        val flags = pi.requestedPermissionsFlags
        if (flags == null || flags.size != perms.size) return perms.toSet()
        val out = HashSet<String>()
        for (i in perms.indices) {
            if (flags[i] and PackageInfo.REQUESTED_PERMISSION_GRANTED != 0) out.add(perms[i])
        }
        return out
    }

    private fun isSideloaded(pm: PackageManager, pkg: String): Boolean {
        val installer = try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R)
                pm.getInstallSourceInfo(pkg).installingPackageName
            else @Suppress("DEPRECATION") pm.getInstallerPackageName(pkg)
        } catch (_: Exception) { null }
        return installer == null || installer !in PLAY_STORES
    }

    private fun appOpAllowed(ops: AppOpsManager?, op: String, uid: Int, pkg: String): Boolean {
        if (ops == null) return false
        return try {
            val mode = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q)
                ops.unsafeCheckOpNoThrow(op, uid, pkg)
            else @Suppress("DEPRECATION") ops.checkOpNoThrow(op, uid, pkg)
            mode == AppOpsManager.MODE_ALLOWED
        } catch (_: Exception) { false }
    }

    /** Parsea una lista de componentes ("pkg/.Servicio:pkg2/...") a un set de paquetes. */
    private fun enabledServicePkgs(ctx: Context, secureKey: String): Set<String> {
        val raw = try { Settings.Secure.getString(ctx.contentResolver, secureKey) } catch (_: Exception) { null }
            ?: return emptySet()
        return raw.split(':')
            .mapNotNull { it.substringBefore('/').takeIf { p -> p.isNotBlank() } }
            .toSet()
    }

    private fun deviceAdminPkgs(ctx: Context): Set<String> {
        val dpm = ctx.getSystemService(Context.DEVICE_POLICY_SERVICE) as? DevicePolicyManager
            ?: return emptySet()
        return try { dpm.activeAdmins?.map { it.packageName }?.toSet() ?: emptySet() }
        catch (_: Exception) { emptySet() }
    }
}
