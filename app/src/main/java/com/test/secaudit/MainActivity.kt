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
 * 设备安全审计工具：系统/开发者/连接/隐私检查（同步）+ 应用分析（异步）
 * 使用复合条件扫描隐藏或可疑应用。计算 0-100 分，提供"修复"按钮跳转至设置，
 * 并支持导出 HTML 报告。
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
        
    contentRoot.addView(categoryHeader("应用"))
    lastRenderedCategory = "应用"
    val loading = TextView(this).apply {
        text = "正在分析应用…"
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
        "系统", "Root",
        if (rooted) Sev.WARN else Sev.GOOD,
        if (rooted) "检测到 Root 迹象。安卓安全模型已被破坏。"
        else "未检测到 Root 迹象。"
    )
}

private fun checkSelinux(): Check {
    val enforce = File("/sys/fs/selinux/enforce")
    val read = runCatching { enforce.readText().trim() }
    if (read.isSuccess) {
        return when (read.getOrNull()) {
            "1" -> Check("系统", "SELinux", Sev.GOOD, "SELinux 处于 ENFORCING 模式。")
            "0" -> Check("系统", "SELinux", Sev.WARN, "SELinux 处于 PERMISSIVE 模式。")
            else -> Check("系统", "SELinux", Sev.GOOD, "SELinux 活跃（状态不明确）。")
        }
    }
    return Check(
        "系统", "SELinux", Sev.GOOD,
        "SELinux 处于 ENFORCING 模式（策略阻止应用读取其状态；如果是 permissive 模式则不会）。"
    )
}

private fun checkEncryption(): Check {
    val dpm = getSystemService(Context.DEVICE_POLICY_SERVICE) as DevicePolicyManager
    val status = dpm.storageEncryptionStatus
    val encrypted = status == DevicePolicyManager.ENCRYPTION_STATUS_ACTIVE ||
        (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N &&
            status == DevicePolicyManager.ENCRYPTION_STATUS_ACTIVE_PER_USER)
    return Check(
        "系统", "存储加密",
        if (encrypted) Sev.GOOD else Sev.WARN,
        if (encrypted) "存储已加密，保护您的数据免受物理访问。"
        else "存储未加密或无法确定。",
        fix = listOf(Intent(Settings.ACTION_SECURITY_SETTINGS))
    )
}

private fun checkScreenLock(): Check {
    val km = getSystemService(Context.KEYGUARD_SERVICE) as KeyguardManager
    val secure = km.isDeviceSecure
    return Check(
        "系统", "屏幕锁",
        if (secure) Sev.GOOD else Sev.WARN,
        if (secure) "已配置 PIN、图案或密码。"
        else "未设置安全锁：任何人拿到设备都能访问您的数据。",
        fix = listOf(
            Intent(DevicePolicyManager.ACTION_SET_NEW_PASSWORD),
            Intent(Settings.ACTION_SECURITY_SETTINGS)
        )
    )
}

private fun checkSecurityPatch(): Check {
    if (Build.VERSION.SDK_INT < Build.VERSION_CODES.M) {
        return Check("系统", "安全补丁", Sev.INFO, "此版本不可用。")
    }
    val patch = Build.VERSION.SECURITY_PATCH
    val days = try {
        val fmt = SimpleDateFormat("yyyy-MM-dd", Locale.US)
        val patchMs = fmt.parse(patch)?.time ?: 0L
        (System.currentTimeMillis() - patchMs) / 86_400_000L
    } catch (_: Exception) { -1L }

    return when {
        days < 0 -> Check("系统", "安全补丁", Sev.INFO, "补丁日期：$patch")
        days > 180 -> Check(
            "系统", "安全补丁", Sev.WARN,
            "补丁日期：$patch（$days 天前）。设备可能存在未修复的漏洞，请更新。",
            fix = listOf(
                Intent().setClassName("com.google.android.gms", "com.google.android.gms.update.SystemUpdateActivity"),
                Intent("android.settings.SYSTEM_UPDATE_SETTINGS").setPackage("com.google.android.gms"),
                Intent("android.settings.SYSTEM_UPDATE_SETTINGS"),
                Intent(Settings.ACTION_DEVICE_INFO_SETTINGS)
            )
        )
        else -> Check(
            "系统", "安全补丁", Sev.GOOD,
            "补丁日期：$patch（$days 天前）。相对最新。"
        )
    }
}

private fun checkBuildTags(): Check {
    val tags = Build.TAGS ?: ""
    val official = tags.contains("release-keys") && !tags.contains("test-keys")
    return Check(
        "系统", "官方固件",
        if (official) Sev.GOOD else Sev.WARN,
        if (official) "构建使用 release-keys 签名（官方固件）。"
        else "构建标签：$tags。可能是自定义 ROM 或非官方固件，补丁可能过时。"
    )
}

private fun checkPlayProtect(): Check {
    val gms = try { packageManager.getPackageInfo("com.google.android.gms", 0); true } catch (_: Exception) { false }
    return Check(
        "系统", "Google Play Protect",
        if (gms) Sev.GOOD else Sev.INFO,
        if (gms) "已检测到 Google Play 服务。Play Protect 可扫描应用。请在 Play 商店中确认其已开启。"
        else "未检测到 Google Play 服务。如果从商店外部安装应用，请考虑使用防病毒软件。"
    )
}

private fun checkAdbBackup(): Check {
    val allow = (applicationInfo.flags and ApplicationInfo.FLAG_ALLOW_BACKUP) != 0
    return Check(
        "开发者", "ADB 备份",
        if (allow) Sev.WARN else Sev.GOOD,
        if (allow) "ADB 备份已启用：此应用的数据可通过 USB 提取。"
        else "ADB 备份已禁用。"
    )
}

private fun checkUnknownSources(): Check {
    return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
        val can = try {
            packageManager.canRequestPackageInstalls()
        } catch (_: Exception) {
            return Check(
                "开发者", "未知来源", Sev.INFO,
                "无法确定（Android 8+ 为按应用授权）。请检查 设置 › 特殊应用权限。"
            )
        }
        Check(
            "开发者", "未知来源",
            if (can) Sev.WARN else Sev.GOOD,
            if (can) "此应用可安装外部 APK（Android 8+ 按应用授权模式）。"
            else "此应用的外部 APK 安装被限制。",
            fix = listOf(
                Intent(Settings.ACTION_MANAGE_UNKNOWN_APP_SOURCES, Uri.parse("package:$packageName")),
                Intent(Settings.ACTION_SECURITY_SETTINGS)
            )
        )
    } else {
        @Suppress("DEPRECATION")
        val on = Settings.Secure.getInt(contentResolver, Settings.Secure.INSTALL_NON_MARKET_APPS, 0) == 1
        Check(
            "开发者", "未知来源",
            if (on) Sev.WARN else Sev.GOOD,
            if (on) "允许安装来自未知来源的应用。" else "仅允许安装来自官方商店的应用。"
        )
    }
}

private fun checkWifi(): Check {
    val cm = getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
    val caps = cm.getNetworkCapabilities(cm.activeNetwork)
    val onWifi = caps?.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) == true
    return Check(
        "连接", "WiFi", Sev.INFO,
        if (onWifi) "已连接 WiFi。敏感数据请避免使用公共网络。"
        else "没有活跃的 WiFi 连接。"
    )
}

private fun checkBluetooth(): Check {
    val on = Settings.Global.getInt(contentResolver, "bluetooth_on", 0) == 1
    return Check(
        "连接", "蓝牙", Sev.INFO,
        if (on) "蓝牙已开启。不使用时请关闭。" else "蓝牙已关闭。"
    )
}

private fun checkNfc(): Check {
    val adapter = NfcAdapter.getDefaultAdapter(this)
    return when {
        adapter == null -> Check("连接", "NFC", Sev.INFO, "无 NFC 硬件。")
        adapter.isEnabled -> Check("连接", "NFC", Sev.INFO, "NFC 已开启。")
        else -> Check("连接", "NFC", Sev.INFO, "NFC 已关闭。")
    }
}

private fun checkUserCaCerts(): Check {
    val userAliases = try {
        val ks = KeyStore.getInstance("AndroidCAStore")
        ks.load(null)
        Collections.list(ks.aliases()).filter { it.startsWith("user:") }
    } catch (_: Exception) { emptyList() }
    return if (userAliases.isEmpty())
        Check("隐私", "用户 CA 证书", Sev.GOOD,
            "用户未添加根证书。TLS 流量无法被外部 CA 拦截。")
    else
        Check("隐私", "用户 CA 证书", Sev.WARN,
            "${userAliases.size} 个根证书由用户或组织添加。" +
                "可能允许 HTTPS 流量拦截（中间人攻击）。如不认可请审查。",
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
        show == 0 -> Check("隐私", "锁屏通知", Sev.GOOD,
            "手机锁定时不显示通知。")
        priv == 1 -> Check("隐私", "锁屏通知", Sev.WARN,
            "锁屏上可见通知内容（含两步验证码）。",
            fix = notifFix)
        else -> Check("隐私", "锁屏通知", Sev.GOOD,
            "显示通知，但敏感内容在锁屏上隐藏。")
    }
}

private fun appSummaryChecks(r: ScanResult): List<Check> {
    val out = ArrayList<Check>()
    val n = r.flagged.size
    out.add(Check(
        "应用", "可疑应用",
        if (n > 0) Sev.WARN else Sev.GOOD,
        if (n > 0) "${r.totalUserApps} 个用户应用中有 $n 个应用组合了风险信号。请逐个审查。"
        else "${r.totalUserApps} 个用户应用中无应用组合风险信号。",
        actionLabel = if (n > 0) "查看被标记的应用（$n）" else null,
        onAction = if (n > 0) ({ startActivity(Intent(this, AppListActivity::class.java)) }) else null
    ))
    out.add(Check(
        "应用", "隐藏应用",
        when {
            r.hiddenRisky -> Sev.WARN
            r.hidden.isNotEmpty() -> Sev.INFO
            else -> Sev.GOOD
        },
        if (r.hidden.isNotEmpty())
            "${r.hidden.size} 个用户应用无启动器图标：${r.hidden.joinToString(", ") { it.label }}。" +
                "无图标可能是正常组件，也可能是隐藏间谍软件；请检查您不认识的程序。"
        else "所有用户应用都有可见的启动器图标。"
    ))
    out.add(Check(
        "应用", "无障碍服务",
        if (r.accessibility.isNotEmpty()) Sev.WARN else Sev.GOOD,
        if (r.accessibility.isNotEmpty())
            "拥有无障碍权限的应用（可读取屏幕和模拟点击）：${r.accessibility.joinToString(", ")}。"
        else "没有第三方应用使用无障碍服务。",
        fix = if (r.accessibility.isNotEmpty()) listOf(Intent(Settings.ACTION_ACCESSIBILITY_SETTINGS)) else emptyList()
    ))
    out.add(Check(
        "应用", "通知访问",
        if (r.notifListeners.isNotEmpty()) Sev.WARN else Sev.GOOD,
        if (r.notifListeners.isNotEmpty())
            "可读取所有通知（含两步验证码）的应用：${r.notifListeners.joinToString(", ")}。"
        else "没有第三方应用读取您的通知。",
        fix = if (r.notifListeners.isNotEmpty())
            listOf(Intent("android.settings.ACTION_NOTIFICATION_LISTENER_SETTINGS")) else emptyList()
    ))
    out.add(Check(
        "应用", "设备管理员",
        if (r.deviceAdmins.isNotEmpty()) Sev.WARN else Sev.GOOD,
        if (r.deviceAdmins.isNotEmpty())
            "拥有设备管理员权限的应用（可抵抗卸载）：${r.deviceAdmins.joinToString(", ")}。"
        else "没有第三方应用是设备管理员。",
        fix = if (r.deviceAdmins.isNotEmpty()) listOf(Intent(Settings.ACTION_SECURITY_SETTINGS)) else emptyList()
    ))
    out.add(Check(
        "应用", "侧载应用", Sev.INFO,
        "${r.sideloadedCount} 个应用来自 Google Play 之外。本身不一定有问题，但这是恶意软件的常见途径。"
    ))
    return out
}

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
                text = "设备安全审计"
                textSize = 13f
                setTextColor(col(R.color.textSecondary))
            })
        })
    })

    scoreNumber = TextView(this).apply {
        text = "$score"
        textSize = 44f
        setTextColor(scoreColor(score))
        setTypeface(typeface, Typeface.BOLD)
    }
    barFilled = View(this).apply { background = rounded(scoreColor(score), px(6)) }
    barEmpty = View(this)
    scoreSub = TextView(this).apply {
        text = "$good / $scorable 项检查通过"
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
        addView(makeButton("分享报告", filled = true) { exportReport() },
            LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT).apply { topMargin = px(14) })
    }, LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT).apply { topMargin = px(18) })

    renderChecks(allChecks)

    return ScrollView(this).apply {
        isFillViewport = true
        addView(contentRoot)
    }
}
