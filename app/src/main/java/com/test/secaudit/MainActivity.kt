package com.test.secaudit

import android.app.KeyguardManager
import android.app.admin.DevicePolicyManager
import android.content.Context
import android.content.Intent
import android.content.pm.ApplicationInfo
import android.graphics.Typeface
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.net.Uri
import android.nfc.NfcAdapter
import android.os.Build
import android.os.Bundle
import android.provider.Settings
import android.view.Gravity
import android.view.View
import android.view.ViewGroup.LayoutParams.MATCH_PARENT
import android.view.ViewGroup.LayoutParams.WRAP_CONTENT
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import android.widget.Toast
import androidx.core.content.FileProvider
import java.io.File
import java.security.KeyStore
import java.text.SimpleDateFormat
import java.util.Collections
import java.util.Date
import java.util.Locale
import java.util.concurrent.Executors

/**
 * Auditor de seguridad del dispositivo: chequeos de Sistema/Desarrollador/Conectividad/
 * Privacidad (síncronos) + análisis del parque de aplicaciones (asíncrono) buscando apps
 * ocultas o sospechosas con criterio compuesto. Calcula un puntaje 0-100, ofrece botones
 * "Solucionar" hacia Ajustes y exporta un informe HTML.
 */
class MainActivity : BaseSecActivity() {

    private data class Check(
        val category: String,
        val title: String,
        val sev: Sev,
        val detail: String,
        val fix: List<Intent> = emptyList(),
        val actionLabel: String? = null,
        val onAction: (() -> Unit)? = null
    )

    private val allChecks = mutableListOf<Check>()
    private var scanDone = false
    private var lastRenderedCategory = ""

    private lateinit var contentRoot: LinearLayout
    private lateinit var scoreNumber: TextView
    private lateinit var scoreSub: TextView
    private lateinit var barFilled: View
    private lateinit var barEmpty: View

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        allChecks.addAll(runDeviceChecks())
        setContentView(buildBaseUi())

        // Sección de apps: header + placeholder, y escaneo en segundo plano.
        contentRoot.addView(categoryHeader("Aplicaciones"))
        lastRenderedCategory = "Aplicaciones"
        val loading = TextView(this).apply {
            text = "Analizando aplicaciones…"
            textSize = 13f
            setTextColor(col(R.color.textSecondary))
            setPadding(px(4), px(2), 0, px(4))
        }
        contentRoot.addView(loading)

        Executors.newSingleThreadExecutor().execute {
            val result = AppScanner.scan(this)
            runOnUiThread {
                if (isFinishing || isDestroyed) return@runOnUiThread
                contentRoot.removeView(loading)
                val appChecks = appSummaryChecks(result)
                allChecks.addAll(appChecks)
                for (c in appChecks) {
                    contentRoot.addView(buildCard(c), LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT).apply {
                        topMargin = px(10)
                    })
                }
                scanDone = true
                updateScore()
            }
        }
    }

    private fun runDeviceChecks(): List<Check> = listOf(
        checkRoot(), checkSelinux(), checkEncryption(), checkScreenLock(),
        checkSecurityPatch(), checkBuildTags(), checkPlayProtect(), checkPlayProtectVerifier(),
        infoAndroidVersion(),
        checkDeveloperOptions(), checkUsbDebugging(), checkAdbWifi(), checkAdbBackup(), checkUnknownSources(),
        checkWifi(), checkBluetooth(), checkNfc(),
        checkUserCaCerts(), checkLockScreenNotifications()
    )

    // =========================================================== Sistema

    private fun checkRoot(): Check {
        val suPaths = listOf(
            "/system/bin/su", "/system/xbin/su", "/sbin/su",
            "/system/bin/failsafe/su", "/data/local/su",
            "/data/local/bin/su", "/data/local/xbin/su",
            "/system/sd/xbin/su", "/system/xbin/busybox"
        )
        val managers = listOf("com.topjohnwu.magisk", "io.github.huskydg.magisk")
        val foundBinary = suPaths.any { File(it).exists() }
        val foundManager = managers.any {
            try { packageManager.getPackageInfo(it, 0); true } catch (_: Exception) { false }
        }
        val canExecSu = try {
            val p = Runtime.getRuntime().exec(arrayOf("which", "su"))
            val out = p.inputStream.bufferedReader().readText().trim()
            p.waitFor(); out.isNotEmpty()
        } catch (_: Exception) { false }

        val rooted = foundBinary || foundManager || canExecSu
        return Check(
            "Sistema", "Root",
            if (rooted) Sev.WARN else Sev.GOOD,
            if (rooted) "Se detectaron indicadores de root. El modelo de seguridad de Android está comprometido."
            else "No se detectaron indicadores de root."
        )
    }

    private fun checkSelinux(): Check {
        val enforce = File("/sys/fs/selinux/enforce")
        val read = runCatching { enforce.readText().trim() }
        if (read.isSuccess) {
            return when (read.getOrNull()) {
                "1" -> Check("Sistema", "SELinux", Sev.GOOD, "SELinux en modo ENFORCING.")
                "0" -> Check("Sistema", "SELinux", Sev.WARN, "SELinux en modo PERMISSIVE.")
                else -> Check("Sistema", "SELinux", Sev.GOOD, "SELinux activo (estado no concluyente).")
            }
        }
        return Check(
            "Sistema", "SELinux", Sev.GOOD,
            "SELinux en modo ENFORCING (la política bloquea la lectura del estado a las apps; " +
                "en permissive no se bloquearía)."
        )
    }

    private fun checkEncryption(): Check {
        val dpm = getSystemService(Context.DEVICE_POLICY_SERVICE) as DevicePolicyManager
        val status = dpm.storageEncryptionStatus
        val encrypted = status == DevicePolicyManager.ENCRYPTION_STATUS_ACTIVE ||
            (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N &&
                status == DevicePolicyManager.ENCRYPTION_STATUS_ACTIVE_PER_USER)
        return Check(
            "Sistema", "Cifrado de almacenamiento",
            if (encrypted) Sev.GOOD else Sev.WARN,
            if (encrypted) "El almacenamiento está cifrado. Protege tus datos ante acceso físico."
            else "El almacenamiento NO está cifrado o no se pudo determinar.",
            fix = listOf(Intent(Settings.ACTION_SECURITY_SETTINGS))
        )
    }

    private fun checkScreenLock(): Check {
        val km = getSystemService(Context.KEYGUARD_SERVICE) as KeyguardManager
        val secure = km.isDeviceSecure
        return Check(
            "Sistema", "Bloqueo de pantalla",
            if (secure) Sev.GOOD else Sev.WARN,
            if (secure) "Hay PIN, patrón o contraseña configurados."
            else "Sin bloqueo seguro: cualquiera con el equipo accede a tus datos.",
            fix = listOf(
                Intent(DevicePolicyManager.ACTION_SET_NEW_PASSWORD),
                Intent(Settings.ACTION_SECURITY_SETTINGS)
            )
        )
    }

    private fun checkSecurityPatch(): Check {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.M) {
            return Check("Sistema", "Parche de seguridad", Sev.INFO, "No disponible en esta versión.")
        }
        val patch = Build.VERSION.SECURITY_PATCH
        val days = try {
            val fmt = SimpleDateFormat("yyyy-MM-dd", Locale.US)
            val patchMs = fmt.parse(patch)?.time ?: 0L
            (System.currentTimeMillis() - patchMs) / 86_400_000L
        } catch (_: Exception) { -1L }

        return when {
            days < 0 -> Check("Sistema", "Parche de seguridad", Sev.INFO, "Parche: $patch")
            days > 180 -> Check(
                "Sistema", "Parche de seguridad", Sev.WARN,
                "Parche: $patch (hace $days días). El dispositivo puede tener vulnerabilidades sin parchear; actualizá.",
                fix = listOf(
                    // El updater del OEM (Motorola) está protegido por permiso de firma y no es
                    // lanzable; el de Google Play Services sí abre el chequeo de updates.
                    Intent().setClassName("com.google.android.gms", "com.google.android.gms.update.SystemUpdateActivity"),
                    Intent("android.settings.SYSTEM_UPDATE_SETTINGS").setPackage("com.google.android.gms"),
                    Intent("android.settings.SYSTEM_UPDATE_SETTINGS"),
                    Intent(Settings.ACTION_DEVICE_INFO_SETTINGS)
                )
            )
            else -> Check(
                "Sistema", "Parche de seguridad", Sev.GOOD,
                "Parche: $patch (hace $days días). Razonablemente al día."
            )
        }
    }

    private fun checkBuildTags(): Check {
        val tags = Build.TAGS ?: ""
        val official = tags.contains("release-keys") && !tags.contains("test-keys")
        return Check(
            "Sistema", "Firmware oficial",
            if (official) Sev.GOOD else Sev.WARN,
            if (official) "Build firmado con release-keys (firmware oficial)."
            else "Build tags: $tags. Posible ROM custom o firmware no oficial; los parches pueden estar desactualizados."
        )
    }

    private fun checkPlayProtect(): Check {
        val gms = try { packageManager.getPackageInfo("com.google.android.gms", 0); true } catch (_: Exception) { false }
        return Check(
            "Sistema", "Google Play Protect",
            if (gms) Sev.GOOD else Sev.INFO,
            if (gms) "Google Play Services detectado. Play Protect puede analizar apps. Verificá que esté activo en Play Store."
            else "Sin Google Play Services. Considerá un antivirus si instalás apps de fuera de la tienda."
        )
    }

    private fun checkPlayProtectVerifier(): Check {
        var v = Settings.Global.getInt(contentResolver, "package_verifier_enable", -1)
        if (v == -1) v = Settings.Secure.getInt(contentResolver, "package_verifier_enable", 1)
        val enabled = v != 0
        return Check(
            "Sistema", "Verificador de apps",
            if (enabled) Sev.GOOD else Sev.WARN,
            if (enabled) "El verificador de Google (Play Protect) escanea apps al instalarlas."
            else "El verificador de apps está desactivado: las apps no se escanean al instalar.",
            fix = if (enabled) emptyList() else listOf(Intent(Settings.ACTION_SECURITY_SETTINGS))
        )
    }

    private fun infoAndroidVersion(): Check = Check(
        "Sistema", "Versión de Android", Sev.INFO,
        "Android ${Build.VERSION.RELEASE} (API ${Build.VERSION.SDK_INT}) · ${Build.MANUFACTURER} ${Build.MODEL}"
    )

    // ====================================================== Desarrollador

    private fun checkDeveloperOptions(): Check {
        val on = Settings.Global.getInt(contentResolver, Settings.Global.DEVELOPMENT_SETTINGS_ENABLED, 0) == 1
        return Check(
            "Desarrollador", "Opciones de desarrollador",
            if (on) Sev.WARN else Sev.GOOD,
            if (on) "Activadas. Si no sos desarrollador, desactivalas en Ajustes." else "Desactivadas.",
            fix = listOf(
                Intent(Settings.ACTION_APPLICATION_DEVELOPMENT_SETTINGS),
                Intent(Settings.ACTION_DEVICE_INFO_SETTINGS)
            )
        )
    }

    private fun checkUsbDebugging(): Check {
        val on = Settings.Global.getInt(contentResolver, Settings.Global.ADB_ENABLED, 0) == 1
        return Check(
            "Desarrollador", "USB Debugging (ADB)",
            if (on) Sev.WARN else Sev.GOOD,
            if (on) "USB debugging ACTIVADO. Desactivalo si no lo necesitás." else "USB debugging desactivado.",
            fix = listOf(Intent(Settings.ACTION_APPLICATION_DEVELOPMENT_SETTINGS))
        )
    }

    private fun checkAdbWifi(): Check {
        val on = Settings.Global.getInt(contentResolver, "adb_wifi_enabled", 0) == 1
        return Check(
            "Desarrollador", "ADB por WiFi",
            if (on) Sev.WARN else Sev.GOOD,
            if (on) "Depuración inalámbrica activada: el dispositivo es accesible por ADB en la red local."
            else "Depuración inalámbrica desactivada.",
            fix = if (on) listOf(Intent(Settings.ACTION_APPLICATION_DEVELOPMENT_SETTINGS)) else emptyList()
        )
    }

    private fun checkAdbBackup(): Check {
        val allow = (applicationInfo.flags and ApplicationInfo.FLAG_ALLOW_BACKUP) != 0
        return Check(
            "Desarrollador", "Backup ADB",
            if (allow) Sev.WARN else Sev.GOOD,
            if (allow) "Backup ADB habilitado: los datos de esta app pueden extraerse por USB."
            else "Backup ADB desactivado."
        )
    }

    private fun checkUnknownSources(): Check {
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val can = try {
                packageManager.canRequestPackageInstalls()
            } catch (_: Exception) {
                return Check(
                    "Desarrollador", "Fuentes desconocidas", Sev.INFO,
                    "No se pudo determinar (modelo por-app de Android 8+). Revisá en Ajustes › Apps con acceso especial."
                )
            }
            Check(
                "Desarrollador", "Fuentes desconocidas",
                if (can) Sev.WARN else Sev.GOOD,
                if (can) "Esta app puede instalar APKs externas (modelo por-app de Android 8+)."
                else "Instalación de APKs externas restringida para esta app.",
                fix = listOf(
                    Intent(Settings.ACTION_MANAGE_UNKNOWN_APP_SOURCES, Uri.parse("package:$packageName")),
                    Intent(Settings.ACTION_SECURITY_SETTINGS)
                )
            )
        } else {
            @Suppress("DEPRECATION")
            val on = Settings.Secure.getInt(contentResolver, Settings.Secure.INSTALL_NON_MARKET_APPS, 0) == 1
            Check(
                "Desarrollador", "Fuentes desconocidas",
                if (on) Sev.WARN else Sev.GOOD,
                if (on) "Permitida la instalación de apps de fuentes desconocidas." else "Solo apps de la tienda oficial."
            )
        }
    }

    // ======================================================= Conectividad

    private fun checkWifi(): Check {
        val cm = getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        val caps = cm.getNetworkCapabilities(cm.activeNetwork)
        val onWifi = caps?.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) == true
        return Check(
            "Conectividad", "Red WiFi", Sev.INFO,
            if (onWifi) "Conectado por WiFi. Evitá redes públicas para datos sensibles."
            else "Sin conexión WiFi activa."
        )
    }

    private fun checkBluetooth(): Check {
        val on = Settings.Global.getInt(contentResolver, "bluetooth_on", 0) == 1
        return Check(
            "Conectividad", "Bluetooth", Sev.INFO,
            if (on) "Bluetooth activado. Desactivalo si no lo usás." else "Bluetooth desactivado."
        )
    }

    private fun checkNfc(): Check {
        val adapter = NfcAdapter.getDefaultAdapter(this)
        return when {
            adapter == null -> Check("Conectividad", "NFC", Sev.INFO, "Sin hardware NFC.")
            adapter.isEnabled -> Check("Conectividad", "NFC", Sev.INFO, "NFC activado.")
            else -> Check("Conectividad", "NFC", Sev.INFO, "NFC desactivado.")
        }
    }

    // ========================================================= Privacidad

    private fun checkUserCaCerts(): Check {
        val userAliases = try {
            val ks = KeyStore.getInstance("AndroidCAStore")
            ks.load(null)
            Collections.list(ks.aliases()).filter { it.startsWith("user:") }
        } catch (_: Exception) { emptyList() }
        return if (userAliases.isEmpty())
            Check("Privacidad", "Certificados CA de usuario", Sev.GOOD,
                "Sin certificados raíz agregados por el usuario. El tráfico TLS no es interceptable por CAs externas.")
        else
            Check("Privacidad", "Certificados CA de usuario", Sev.WARN,
                "${userAliases.size} certificado(s) raíz agregados por el usuario o una empresa. " +
                    "Pueden permitir interceptar tráfico HTTPS (MITM). Revisalos si no los reconocés.",
                fix = listOf(Intent(Settings.ACTION_SECURITY_SETTINGS)))
    }

    private fun checkLockScreenNotifications(): Check {
        val show = Settings.Secure.getInt(contentResolver, "lock_screen_show_notifications", 1)
        val priv = Settings.Secure.getInt(contentResolver, "lock_screen_allow_private_notifications", 1)
        val notifFix = listOf(
            Intent("android.settings.NOTIFICATION_SETTINGS"),
            Intent(Settings.ACTION_SETTINGS)
        )
        return when {
            show == 0 -> Check("Privacidad", "Notif. en pantalla bloqueada", Sev.GOOD,
                "Las notificaciones no se muestran con el teléfono bloqueado.")
            priv == 1 -> Check("Privacidad", "Notif. en pantalla bloqueada", Sev.WARN,
                "El contenido de las notificaciones (incluidos códigos 2FA) es visible con el teléfono bloqueado.",
                fix = notifFix)
            else -> Check("Privacidad", "Notif. en pantalla bloqueada", Sev.GOOD,
                "Se muestran notificaciones pero con el contenido sensible oculto en el bloqueo.")
        }
    }

    // ====================================================== Resumen apps

    private fun appSummaryChecks(r: ScanResult): List<Check> {
        val out = ArrayList<Check>()
        val n = r.flagged.size
        out.add(Check(
            "Aplicaciones", "Apps sospechosas",
            if (n > 0) Sev.WARN else Sev.GOOD,
            if (n > 0) "$n app(s) combinan señales de riesgo (sobre ${r.totalUserApps} de usuario). Revisalas una por una."
            else "Ninguna app combina señales de riesgo (sobre ${r.totalUserApps} apps de usuario).",
            actionLabel = if (n > 0) "Ver apps marcadas ($n)" else null,
            onAction = if (n > 0) ({ startActivity(Intent(this, AppListActivity::class.java)) }) else null
        ))
        out.add(Check(
            "Aplicaciones", "Apps ocultas",
            when {
                r.hiddenRisky -> Sev.WARN          // oculta + origen no confiable = patrón de spyware
                r.hidden.isNotEmpty() -> Sev.INFO  // suelen ser componentes del sistema sin lanzador
                else -> Sev.GOOD
            },
            if (r.hidden.isNotEmpty())
                "${r.hidden.size} app(s) de usuario sin ícono en el cajón: ${r.hidden.joinToString(", ") { it.label }}. " +
                    "Sin ícono puede ser un componente legítimo o spyware que se esconde; revisá las que no reconozcas."
            else "Todas las apps de usuario tienen ícono visible."
        ))
        out.add(Check(
            "Aplicaciones", "Servicios de accesibilidad",
            if (r.accessibility.isNotEmpty()) Sev.WARN else Sev.GOOD,
            if (r.accessibility.isNotEmpty())
                "Apps con accesibilidad (pueden leer la pantalla y simular toques): ${r.accessibility.joinToString(", ")}."
            else "Ninguna app de terceros usa accesibilidad.",
            fix = if (r.accessibility.isNotEmpty()) listOf(Intent(Settings.ACTION_ACCESSIBILITY_SETTINGS)) else emptyList()
        ))
        out.add(Check(
            "Aplicaciones", "Acceso a notificaciones",
            if (r.notifListeners.isNotEmpty()) Sev.WARN else Sev.GOOD,
            if (r.notifListeners.isNotEmpty())
                "Apps que leen todas las notificaciones (incluidos códigos 2FA): ${r.notifListeners.joinToString(", ")}."
            else "Ninguna app de terceros lee tus notificaciones.",
            fix = if (r.notifListeners.isNotEmpty())
                listOf(Intent("android.settings.ACTION_NOTIFICATION_LISTENER_SETTINGS")) else emptyList()
        ))
        out.add(Check(
            "Aplicaciones", "Administradores de dispositivo",
            if (r.deviceAdmins.isNotEmpty()) Sev.WARN else Sev.GOOD,
            if (r.deviceAdmins.isNotEmpty())
                "Apps con admin de dispositivo (resisten desinstalación): ${r.deviceAdmins.joinToString(", ")}."
            else "Ninguna app de terceros es administrador del dispositivo.",
            fix = if (r.deviceAdmins.isNotEmpty()) listOf(Intent(Settings.ACTION_SECURITY_SETTINGS)) else emptyList()
        ))
        out.add(Check(
            "Aplicaciones", "Apps fuera de Play Store", Sev.INFO,
            "${r.sideloadedCount} app(s) instaladas fuera de Google Play. No es malo en sí, pero es la vía habitual del malware."
        ))
        return out
    }

    // ================================================================ UI

    private fun computeScore(): Triple<Int, Int, Int> {
        val good = allChecks.count { it.sev == Sev.GOOD }
        val scorable = allChecks.count { it.sev != Sev.INFO }
        val score = if (scorable == 0) 100 else (good * 100) / scorable
        return Triple(score, good, scorable)
    }

    private fun scoreColor(score: Int) = if (score >= 80) col(R.color.good) else col(R.color.warn)

    private fun categoryHeader(name: String) = TextView(this).apply {
        text = name.uppercase(Locale.getDefault())
        textSize = 12f
        letterSpacing = 0.12f
        setTextColor(col(R.color.accent))
        setTypeface(typeface, Typeface.BOLD)
        setPadding(px(4), px(22), 0, px(8))
    }

    private fun buildBaseUi(): View {
        val (score, good, scorable) = computeScore()

        contentRoot = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(px(18), px(22), px(18), px(28))
        }

        // Encabezado
        contentRoot.addView(LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            addView(ImageView(this@MainActivity).apply {
                setImageResource(R.drawable.ic_shield)
            }, LinearLayout.LayoutParams(px(40), px(40)))
            addView(LinearLayout(this@MainActivity).apply {
                orientation = LinearLayout.VERTICAL
                setPadding(px(12), 0, 0, 0)
                addView(TextView(this@MainActivity).apply {
                    text = "SecAudit"
                    textSize = 24f
                    setTextColor(col(R.color.textPrimary))
                    setTypeface(typeface, Typeface.BOLD)
                })
                addView(TextView(this@MainActivity).apply {
                    text = "Auditoría de seguridad del dispositivo"
                    textSize = 13f
                    setTextColor(col(R.color.textSecondary))
                })
            })
        })

        // Tarjeta de puntaje
        scoreNumber = TextView(this).apply {
            text = "$score"
            textSize = 44f
            setTextColor(scoreColor(score))
            setTypeface(typeface, Typeface.BOLD)
        }
        barFilled = View(this).apply { background = rounded(scoreColor(score), px(6)) }
        barEmpty = View(this)
        scoreSub = TextView(this).apply {
            text = "$good de $scorable controles superados"
            textSize = 13f
            setTextColor(col(R.color.textSecondary))
            setPadding(0, px(10), 0, 0)
        }
        contentRoot.addView(LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            background = rounded(col(R.color.surface), px(18), col(R.color.stroke), px(1))
            setPadding(px(20), px(18), px(20), px(18))
            addView(LinearLayout(this@MainActivity).apply {
                orientation = LinearLayout.HORIZONTAL
                gravity = Gravity.BOTTOM
                addView(scoreNumber)
                addView(TextView(this@MainActivity).apply {
                    text = " / 100"
                    textSize = 16f
                    setTextColor(col(R.color.textSecondary))
                    setPadding(px(4), 0, 0, px(8))
                })
            })
            addView(LinearLayout(this@MainActivity).apply {
                orientation = LinearLayout.HORIZONTAL
                background = rounded(col(R.color.bg), px(6))
                addView(barFilled, LinearLayout.LayoutParams(0, px(8), score.toFloat().coerceAtLeast(1f)))
                addView(barEmpty, LinearLayout.LayoutParams(0, px(8), (100 - score).toFloat()))
            }, LinearLayout.LayoutParams(MATCH_PARENT, px(8)).apply { topMargin = px(12) })
            addView(scoreSub)
            addView(makeButton("Compartir informe", filled = true) { exportReport() },
                LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT).apply { topMargin = px(14) })
        }, LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT).apply { topMargin = px(18) })

        // Chequeos de dispositivo (síncronos)
        renderChecks(allChecks)

        return ScrollView(this).apply {
            isFillViewport = true
            addView(contentRoot)
        }
    }

    private fun renderChecks(list: List<Check>) {
        for (c in list) {
            if (c.category != lastRenderedCategory) {
                lastRenderedCategory = c.category
                contentRoot.addView(categoryHeader(c.category))
            }
            contentRoot.addView(buildCard(c), LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT).apply {
                topMargin = px(10)
            })
        }
    }

    private fun updateScore() {
        val (score, good, scorable) = computeScore()
        scoreNumber.text = "$score"
        scoreNumber.setTextColor(scoreColor(score))
        scoreSub.text = "$good de $scorable controles superados"
        barFilled.background = rounded(scoreColor(score), px(6))
        (barFilled.layoutParams as LinearLayout.LayoutParams).weight = score.toFloat().coerceAtLeast(1f)
        (barEmpty.layoutParams as LinearLayout.LayoutParams).weight = (100 - score).toFloat()
        barFilled.requestLayout()
        barEmpty.requestLayout()
    }

    private fun buildCard(c: Check): View {
        val card = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            background = rounded(col(R.color.surface), px(16), sevColor(c.sev) and 0x55FFFFFF.toInt(), px(1))
            setPadding(px(16), px(14), px(16), px(14))
        }
        card.addView(LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            addView(View(this@MainActivity).apply {
                background = rounded(sevColor(c.sev), px(5))
            }, LinearLayout.LayoutParams(px(9), px(9)).apply { rightMargin = px(10) })
            addView(TextView(this@MainActivity).apply {
                text = c.title
                textSize = 16f
                setTextColor(col(R.color.textPrimary))
                setTypeface(typeface, Typeface.BOLD)
            }, LinearLayout.LayoutParams(0, WRAP_CONTENT, 1f))
            addView(TextView(this@MainActivity).apply {
                text = when (c.sev) { Sev.GOOD -> "OK"; Sev.WARN -> "ALERTA"; Sev.INFO -> "INFO" }
                textSize = 11f
                setTypeface(typeface, Typeface.BOLD)
                setTextColor(sevColor(c.sev))
                background = rounded(sevColor(c.sev) and 0x22FFFFFF.toInt(), px(20))
                setPadding(px(12), px(5), px(12), px(5))
            })
        })
        card.addView(TextView(this).apply {
            text = c.detail
            textSize = 13f
            setTextColor(col(R.color.textSecondary))
            setLineSpacing(px(2).toFloat(), 1f)
            setPadding(px(19), px(7), 0, 0)
        })
        if (c.onAction != null && c.actionLabel != null) {
            card.addView(makeButton(c.actionLabel, filled = true) { c.onAction.invoke() },
                LinearLayout.LayoutParams(WRAP_CONTENT, WRAP_CONTENT).apply {
                    topMargin = px(12); leftMargin = px(19)
                })
        } else if (c.sev == Sev.WARN && c.fix.isNotEmpty()) {
            card.addView(makeButton("Solucionar  ›", filled = false) { launchFirst(c.fix) },
                LinearLayout.LayoutParams(WRAP_CONTENT, WRAP_CONTENT).apply {
                    topMargin = px(10); leftMargin = px(19)
                })
        }
        return card
    }

    // ------------------------------------------------------- Informe HTML

    private fun exportReport() {
        if (!scanDone) {
            Toast.makeText(this, "Analizando aplicaciones, probá en unos segundos…", Toast.LENGTH_SHORT).show()
            return
        }
        try {
            val (score, good, scorable) = computeScore()
            val now = SimpleDateFormat("yyyy-MM-dd HH:mm", Locale.getDefault()).format(Date())
            val scoreHex = if (score >= 80) "#3FB950" else "#F85149"
            val sb = StringBuilder()
            sb.append(
                "<!DOCTYPE html><html lang='es'><head><meta charset='utf-8'>" +
                    "<meta name='viewport' content='width=device-width,initial-scale=1'>" +
                    "<title>Informe SecAudit</title><style>" +
                    "body{margin:0;background:#0D1117;color:#E6EDF3;font-family:system-ui,Segoe UI,Roboto,sans-serif;padding:24px}" +
                    "h1{font-size:22px;margin:0}.sub{color:#8B98A5;font-size:13px;margin:4px 0 20px}" +
                    ".score{font-size:54px;font-weight:800;color:$scoreHex}.score span{font-size:18px;color:#8B98A5}" +
                    ".cat{color:#34D399;font-size:13px;font-weight:700;letter-spacing:.12em;margin:24px 0 8px}" +
                    ".card{background:#161B22;border:1px solid #2A3340;border-radius:14px;padding:14px 16px;margin:10px 0}" +
                    ".row{display:flex;align-items:center;gap:10px}.ttl{font-weight:700;flex:1}" +
                    ".chip{font-size:11px;font-weight:700;padding:4px 10px;border-radius:20px}" +
                    ".det{color:#8B98A5;font-size:13px;margin-top:6px}" +
                    ".good{color:#3FB950}.warn{color:#F85149}.info{color:#58A6FF}" +
                    ".bg-good{background:rgba(63,185,80,.13)}.bg-warn{background:rgba(248,81,73,.13)}.bg-info{background:rgba(88,166,255,.13)}" +
                    "</style></head><body>"
            )
            sb.append("<h1>🛡 SecAudit</h1><div class='sub'>Informe de seguridad · $now · ${Build.MANUFACTURER} ${Build.MODEL} (Android ${Build.VERSION.RELEASE})</div>")
            sb.append("<div class='score'>$score<span> / 100</span></div>")
            sb.append("<div class='sub'>$good de $scorable controles superados</div>")

            var lastCat = ""
            for (c in allChecks) {
                if (c.category != lastCat) {
                    lastCat = c.category
                    sb.append("<div class='cat'>${c.category.uppercase(Locale.getDefault())}</div>")
                }
                val cls = when (c.sev) { Sev.GOOD -> "good"; Sev.WARN -> "warn"; Sev.INFO -> "info" }
                val label = when (c.sev) { Sev.GOOD -> "OK"; Sev.WARN -> "ALERTA"; Sev.INFO -> "INFO" }
                sb.append(
                    "<div class='card'><div class='row'><span class='ttl'>${esc(c.title)}</span>" +
                        "<span class='chip $cls bg-$cls'>$label</span></div>" +
                        "<div class='det'>${esc(c.detail)}</div></div>"
                )
            }
            sb.append("</body></html>")

            val dir = File(cacheDir, "reports").apply { mkdirs() }
            val file = File(dir, "secaudit_${System.currentTimeMillis()}.html")
            file.writeText(sb.toString())

            val uri = FileProvider.getUriForFile(this, "$packageName.fileprovider", file)
            val send = Intent(Intent.ACTION_SEND).apply {
                type = "text/html"
                putExtra(Intent.EXTRA_SUBJECT, "Informe SecAudit")
                putExtra(Intent.EXTRA_STREAM, uri)
                addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
            }
            startActivity(Intent.createChooser(send, "Compartir informe"))
        } catch (e: Exception) {
            Toast.makeText(this, "No se pudo generar el informe: ${e.message}", Toast.LENGTH_SHORT).show()
        }
    }

    private fun esc(s: String) = s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
}
