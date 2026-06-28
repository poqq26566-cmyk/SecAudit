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
 * 设备安全审计工具：系统/开发/连接/隐私检查（同步）+
 * 应用群分析（异步），利用复合特征扫描隐藏或可疑应用。
 * 计算 0-100 的安全评分，提供跳转至设置的“去修复”按钮，并支持导出 HTML 报告。
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

        // 应用分析区域：标题 + 加载提示，后台异步扫描
        contentRoot.addView(categoryHeader("应用风险扫描"))
        lastRenderedCategory = "应用风险扫描"
        val loading = TextView(this).apply {
            text = "正在分析应用列表…"
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
    // =========================================================== 系统安全

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
            "系统安全", "Root 权限",
            if (rooted) Sev.WARN else Sev.GOOD,
            if (rooted) "检测到 Root 痕迹。Android 安全模型已被破坏，存在高风险。"
            else "未检测到 Root 痕迹。"
        )
    }

    private fun checkSelinux(): Check {
        val enforce = File("/sys/fs/selinux/enforce")
        val read = runCatching { enforce.readText().trim() }
        if (read.isSuccess) {
            return when (read.getOrNull()) {
                "1" -> Check("系统安全", "SELinux 状态", Sev.GOOD, "SELinux 处于 强制(ENFORCING) 模式。")
                "0" -> Check("系统安全", "SELinux 状态", Sev.WARN, "SELinux 处于 宽容(PERMISSIVE) 模式，安全防御已降低。")
                else -> Check("系统安全", "SELinux 状态", Sev.GOOD, "SELinux 已启用（未获得确切运行状态）。")
            }
        }
        return Check(
            "系统安全", "SELinux 状态", Sev.GOOD,
            "SELinux 处于 强制(ENFORCING) 模式（安全策略阻止了应用读取状态；若处于宽容模式则不会被阻挡）。"
        )
    }    private fun checkEncryption(): Check {
        val dpm = getSystemService(Context.DEVICE_POLICY_SERVICE) as DevicePolicyManager
        val status = dpm.storageEncryptionStatus
        val encrypted = status == DevicePolicyManager.ENCRYPTION_STATUS_ACTIVE ||
            (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N &&
                status == DevicePolicyManager.ENCRYPTION_STATUS_ACTIVE_PER_USER)
        return Check(
            "系统安全", "存储加密",
            if (encrypted) Sev.GOOD else Sev.WARN,
            if (encrypted) "存储设备已加密。能有效保护您的数据免受物理接触窃取。"
            else "存储未加密或无法确定加密状态，存在数据泄露风险。",
            fix = listOf(Intent(Settings.ACTION_SECURITY_SETTINGS))
        )
    }

    private fun checkScreenLock(): Check {
        val km = getSystemService(Context.KEYGUARD_SERVICE) as KeyguardManager
        val secure = km.isDeviceSecure
        return Check(
            "系统安全", "屏幕锁",
            if (secure) Sev.GOOD else Sev.WARN,
            if (secure) "已配置 PIN 码、图案或密码锁。"
            else "未设置安全锁：任何人拿到手机都能直接访问您的所有数据。",
            fix = listOf(
                Intent(DevicePolicyManager.ACTION_SET_NEW_PASSWORD),
                Intent(Settings.ACTION_SECURITY_SETTINGS)
            )
        )
    }

    private fun checkSecurityPatch(): Check {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.M) {
            return Check("系统安全", "安全补丁", Sev.INFO, "当前系统版本不可用。")
        }
        val patch = Build.VERSION.SECURITY_PATCH
        val days = try {
            val fmt = SimpleDateFormat("yyyy-MM-dd", Locale.US)
            val patchMs = fmt.parse(patch)?.time ?: 0L
            (System.currentTimeMillis() - patchMs) / 86_400_000L
        } catch (_: Exception) { -1L }

        return when {
            days < 0 -> Check("系统安全", "安全补丁", Sev.INFO, "安全补丁版本: $patch")
            days > 180 -> Check(
                "系统安全", "安全补丁", Sev.WARN,
                "安全补丁: $patch (已过期 $days 天)。设备可能存在未修复的漏洞，请尽快更新系统。",
                fix = listOf(
                    Intent().setClassName("com.google.android.gms", "com.google.android.gms.update.SystemUpdateActivity"),
                    Intent("android.settings.SYSTEM_UPDATE_SETTINGS").setPackage("com.google.android.gms"),
                    Intent("android.settings.SYSTEM_UPDATE_SETTINGS"),
                    Intent(Settings.ACTION_DEVICE_INFO_SETTINGS)
                )
            )
            else -> Check(
                "系统安全", "安全补丁", Sev.GOOD,
                "安全补丁: $patch (发布于 $days 天前)。补丁状态良好。"
            )
        }
    }    private fun checkBuildTags(): Check {
        val tags = Build.TAGS ?: ""
        val official = tags.contains("release-keys") && !tags.contains("test-keys")
        return Check(
            "系统安全", "官方固件",
            if (official) Sev.GOOD else Sev.WARN,
            if (official) "固件由官方密钥(release-keys)签名。"
            else "固件标签: $tags。可能是第三方定制 ROM 或非官方固件，补丁可能未及时更新。"
        )
    }

    private fun checkPlayProtect(): Check {
        val gms = try { packageManager.getPackageInfo("com.google.android.gms", 0); true } catch (_: Exception) { false }
        return Check(
            "系统安全", "谷歌应用保护 (Play Protect)",
            if (gms) Sev.GOOD else Sev.INFO,
            if (gms) "检测到 Google Play 服务。Play Protect 可扫描应用，请确保在应用商店中将其开启。"
            else "未检测到 Google Play 服务。如果您经常从外部安装应用，建议使用杀毒软件。"
        )
    }

    private fun checkPlayProtectVerifier(): Check {
        var v = Settings.Global.getInt(contentResolver, "package_verifier_enable", -1)
        if (v == -1) v = Settings.Secure.getInt(contentResolver, "package_verifier_enable", 1)
        val enabled = v != 0
        return Check(
            "系统安全", "应用验证器",
            if (enabled) Sev.GOOD else Sev.WARN,
            if (enabled) "应用验证器已开启（将在安装应用时进行安全性扫描）。"
            else "应用验证器已禁用：安装应用时不会进行安全性扫描。",
            fix = if (enabled) emptyList() else listOf(Intent(Settings.ACTION_SECURITY_SETTINGS))
        )
    }

    private fun infoAndroidVersion(): Check = Check(
        "系统安全", "Android 版本", Sev.INFO,
        "Android ${Build.VERSION.RELEASE} (API ${Build.VERSION.SDK_INT}) · ${Build.MANUFACTURER} ${Build.MODEL}"
    )    // ====================================================== 开发者选项

    private fun checkDeveloperOptions(): Check {
        val on = Settings.Global.getInt(contentResolver, Settings.Global.DEVELOPMENT_SETTINGS_ENABLED, 0) == 1
        return Check(
            "开发者选项", "开发者选项",
            if (on) Sev.WARN else Sev.GOOD,
            if (on) "已启用。如果您不是开发者，建议在系统设置中将其关闭。" else "已禁用。",
            fix = listOf(
                Intent(Settings.ACTION_APPLICATION_DEVELOPMENT_SETTINGS),
                Intent(Settings.ACTION_DEVICE_INFO_SETTINGS)
            )
        )
    }

    private fun checkUsbDebugging(): Check {
        val on = Settings.Global.getInt(contentResolver, Settings.Global.ADB_ENABLED, 0) == 1
        return Check(
            "开发者选项", "USB 调试 (ADB)",
            if (on) Sev.WARN else Sev.GOOD,
            if (on) "USB 调试已开启。如果不需要，请将其关闭以防远程控制。" else "USB 调试已关闭。",
            fix = listOf(Intent(Settings.ACTION_APPLICATION_DEVELOPMENT_SETTINGS))
        )
    }

    private fun checkAdbWifi(): Check {
        val on = Settings.Global.getInt(contentResolver, "adb_wifi_enabled", 0) == 1
        return Check(
            "开发者选项", "无线 ADB 调试",
            if (on) Sev.WARN else Sev.GOOD,
            if (on) "无线调试已激活：在局域网内的设备可通过 ADB 连接此手机。"
            else "无线调试已关闭。",
            fix = if (on) listOf(Intent(Settings.ACTION_APPLICATION_DEVELOPMENT_SETTINGS)) else emptyList()
        )
    }

    private fun checkAdbBackup(): Check {
        val allow = (applicationInfo.flags and ApplicationInfo.FLAG_ALLOW_BACKUP) != 0
        return Check(
            "开发者选项", "ADB 备份权限",
            if (allow) Sev.WARN else Sev.GOOD,
            if (allow) "允许 ADB 备份：该应用的数据可以通过 USB 调试被直接整包导出。"
            else "已禁用 ADB 备份。"
        )
    }    private fun checkUnknownSources(): Check {
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val can = try {
                packageManager.canRequestPackageInstalls()
            } catch (_: Exception) {
                return Check(
                    "开发者选项", "未知来源应用安装", Sev.INFO,
                    "无法确定（Android 8+ 采用单应用授权模式）。请前往“特殊应用权限”检查。"
                )
            }
            Check(
                "开发者选项", "未知来源应用安装",
                if (can) Sev.WARN else Sev.GOOD,
                if (can) "当前应用拥有安装外部 APK 的权限（Android 8+ 单应用授权）。"
                else "当前应用已被限制安装外部 APK。",
                fix = listOf(
                    Intent(Settings.ACTION_MANAGE_UNKNOWN_APP_SOURCES, Uri.parse("package:$packageName")),
                    Intent(Settings.ACTION_SECURITY_SETTINGS)
                )
            )
        } else {
            @Suppress("DEPRECATION")
            val on = Settings.Secure.getInt(contentResolver, Settings.Secure.INSTALL_NON_MARKET_APPS, 0) == 1
            Check(
                "开发者选项", "未知来源应用安装",
                if (on) Sev.WARN else Sev.GOOD,
                if (on) "允许安装来自未知来源的应用，风险较高。" else "仅允许安装来自官方应用商店的应用。"
            )
        }
    }

    // ======================================================= 连接安全

    private fun checkWifi(): Check {
        val cm = getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        val caps = cm.getNetworkCapabilities(cm.activeNetwork)
        val onWifi = caps?.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) == true
        return Check(
            "连接安全", "Wi-Fi 连接", Sev.INFO,
            if (onWifi) "已连接 Wi-Fi。处理敏感数据时请避免使用公共或未加密的网络。"
            else "当前无活跃的 Wi-Fi 连接。"
        )
    }

    private fun checkBluetooth(): Check {
        val on = Settings.Global.getInt(contentResolver, "bluetooth_on", 0) == 1
        return Check(
            "连接安全", "蓝牙状态", Sev.INFO,
            if (on) "蓝牙已开启。不使用时建议将其关闭以防被扫描。" else "蓝牙已关闭。"
        )
    }

    private fun checkNfc(): Check {
        val adapter = NfcAdapter.getDefaultAdapter(this)
        return when {
            adapter == null -> Check("连接安全", "NFC 状态", Sev.INFO, "设备无 NFC 硬件支持。")
            adapter.isEnabled -> Check("连接安全", "NFC 状态", Sev.INFO, "NFC 已开启。")
            else -> Check("连接安全", "NFC 状态", Sev.INFO, "NFC 已关闭。")
        }
    }

    // ========================================================= 隐私安全

    private fun checkUserCaCerts(): Check {
        val userAliases = try {
            val ks = KeyStore.getInstance("AndroidCAStore")
            ks.load(null)
            Collections.list(ks.aliases()).filter { it.startsWith("user:") }
        } catch (_: Exception) { emptyList() }
        return if (userAliases.isEmpty())
            Check("隐私安全", "用户凭据 (CA 证书)", Sev.GOOD,
                "用户未添加自定义根证书。网络传输(TLS)流量无法被外部证书截获。")
        else
            Check("隐私安全", "用户凭据 (CA 证书)", Sev.WARN,
                "用户或组织添加了 ${userAliases.size} 个自定义根证书。这可能会导致您的 HTTPS 流量被监听或截获(MITM)。若非本人操作请立即 review 它们。",
                fix = listOf(Intent(Settings.ACTION_SECURITY_SETTINGS)))
    }    private fun checkLockScreenNotifications(): Check {
        val show = Settings.Secure.getInt(contentResolver, "lock_screen_show_notifications", 1)
        val priv = Settings.Secure.getInt(contentResolver, "lock_screen_allow_private_notifications", 1)
        val notifFix = listOf(
            Intent("android.settings.NOTIFICATION_SETTINGS"),
            Intent(Settings.ACTION_SETTINGS)
        )
        return when {
            show == 0 -> Check("隐私安全", "锁屏通知隐私", Sev.GOOD,
                "手机锁屏时隐藏所有通知。")
            priv == 1 -> Check("隐私安全", "锁屏通知隐私", Sev.WARN,
                "锁屏时显示通知详情：验证码、短信等隐私内容在锁屏界面直接可见！",
                fix = notifFix)
            else -> Check("隐私安全", "锁屏通知隐私", Sev.GOOD,
                "锁屏时显示通知，但已隐藏敏感内容（如短信详情）。")
        }
    }

    // ====================================================== 应用分析部分

    private fun appSummaryChecks(r: ScanResult): List<Check> {
        val out = ArrayList<Check>()
        val n = r.flagged.size
        out.add(Check(
            "应用风险扫描", "可疑应用清单",
            if (n > 0) Sev.WARN else Sev.GOOD,
            if (n > 0) "$n 个应用存在复合风险特征（共扫描了 ${r.totalUserApps} 个用户应用）。请逐一排查。"
            else "未发现存在复合风险特征的应用（共扫描了 ${r.totalUserApps} 个用户应用）。",
            actionLabel = if (n > 0) "查看风险应用 ($n)" else null,
            onAction = if (n > 0) ({ startActivity(Intent(this, AppListActivity::class.java)) }) else null
        ))
        out.add(Check(
            "应用风险扫描", "隐藏应用",
            when {
                r.hiddenRisky -> Sev.WARN
                r.hidden.isNotEmpty() -> Sev.INFO
                else -> Sev.GOOD
            },
            if (r.hidden.isNotEmpty())
                "${r.hidden.size} 个用户应用没有桌面图标：${r.hidden.joinToString(", ") { it.label }}。无图标可能是合法的系统组件，也可能是刻意隐藏的间谍软件，请排查不认识的应用。"
            else "所有用户应用均拥有正常的桌面图标。"
        ))
        out.add(Check(
            "应用风险扫描", "无障碍服务权限",
            if (r.accessibility.isNotEmpty()) Sev.WARN else Sev.GOOD,
            if (r.accessibility.isNotEmpty())
                "以下应用开启了无障碍服务（可读取屏幕内容并模拟点击）：${r.accessibility.joinToString(", ")}。"
            else "没有第三方应用占用无障碍服务。",
            fix = if (r.accessibility.isNotEmpty()) listOf(Intent(Settings.ACTION_ACCESSIBILITY_SETTINGS)) else emptyList()
        ))
        out.add(Check(
            "应用风险扫描", "通知读取权限",
            if (r.notifListeners.isNotEmpty()) Sev.WARN else Sev.GOOD,
            if (r.notifListeners.isNotEmpty())
                "以下应用可读取所有通知（包含短信和二步验证码）：${r.notifListeners.joinToString(", ")}。"
            else "没有第三方应用被授予通知读取权限。",
            fix = if (r.notifListeners.isNotEmpty())
                listOf(Intent("android.settings.ACTION_NOTIFICATION_LISTENER_SETTINGS")) else emptyList()
        ))
        out.add(Check(
            "应用风险扫描", "设备管理器权限",
            if (r.deviceAdmins.isNotEmpty()) Sev.WARN else Sev.GOOD,
            if (r.deviceAdmins.isNotEmpty())
                "以下应用拥有设备管理器权限（可能会阻止用户正常卸载）：${r.deviceAdmins.joinToString(", ")}。"
            else "没有第三方应用激活设备管理器权限。",
            fix = if (r.deviceAdmins.isNotEmpty()) listOf(Intent(Settings.ACTION_SECURITY_SETTINGS)) else emptyList()
        ))
        out.add(Check(
            "应用风险扫描", "外部安装应用", Sev.INFO,
            "${r.sideloadedCount} 个应用是在官方商店之外安装的。这本身并非恶意，但通常是恶意软件侵入的主要途径。"
        ))
        return out
    }    // ================================================================ UI 绘制

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

        // 顶部大标题
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
                    text = "安全审计 (SecAudit)"
                    textSize = 24f
                    setTextColor(col(R.color.textPrimary))
                    setTypeface(typeface, Typeface.BOLD)
                })
                addView(TextView(this@MainActivity).apply {
                    text = "设备安全基线审计"
                    textSize = 13f
                    setTextColor(col(R.color.textSecondary))
                })
            })
        })

        // 分数卡片
        scoreNumber = TextView(this).apply {
            text = "$score"
            textSize = 44f
            setTextColor(scoreColor(score))
            setTypeface(typeface, Typeface.BOLD)
        }
        barFilled = View(this).apply { background = rounded(scoreColor(score), px(6)) }
        barEmpty = View(this)
        scoreSub = TextView(this).apply {
            text = "已通过 $good / $scorable 项安全检查"
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
                    text = " / 100 分"
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
            addView(makeButton("分享/导出报告", filled = true) { exportReport() },
                LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT).apply { topMargin = px(14) })
        }, LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT).apply { topMargin = px(18) })

        // 设备安全同步检查结果渲染
        renderChecks(allChecks)

        return ScrollView(this).apply {
            isFillViewport = true
            addView(contentRoot)
        }
    }    private fun renderChecks(list: List<Check>) {
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
        scoreSub.text = "已通过 $good / $scorable 项安全检查"
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
                text = when (c.sev) { Sev.GOOD -> "正常"; Sev.WARN -> "警告"; Sev.INFO -> "提示" }
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
            card.addView(makeButton("去修复  ›", filled = false) { launchFirst(c.fix) },
                LinearLayout.LayoutParams(WRAP_CONTENT, WRAP_CONTENT).apply {
                    topMargin = px(10); leftMargin = px(19)
                })
        }
        return card
    }

    // ------------------------------------------------------- 生成 HTML 报告

    private fun exportReport() {
        if (!scanDone) {
            Toast.makeText(this, "正在扫描应用，请稍候再试…", Toast.LENGTH_SHORT).show()
            return
        }
        try {
            val (score, good, scorable) = computeScore()
            val now = SimpleDateFormat("yyyy-MM-dd HH:mm", Locale.getDefault()).format(Date())
            val scoreHex = if (score >= 80) "#3FB950" else "#F85149"
            val sb = StringBuilder()
            sb.append(
                "<!DOCTYPE html><html lang='zh-CN'><head><meta charset='utf-8'>" +
                    "<meta name='viewport' content='width=device-width,initial-scale=1'>" +
                    "<title>安全审计报告 (SecAudit)</title><style>" +
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
            sb.append("<h1>🛡 SecAudit 安全审计</h1><div class='sub'>安全检测报告 · $now · ${Build.MANUFACTURER} ${Build.MODEL} (Android ${Build.VERSION.RELEASE})</div>")
            sb.append("<div class='score'>$score<span> / 100 分</span></div>")
            sb.append("<div class='sub'>已通过 $good / $scorable 项安全检查</div>")

            var lastCat = ""
            for (c in allChecks) {
                if (c.category != lastCat) {
                    lastCat = c.category
                    sb.append("<div class='cat'>${c.category.uppercase(Locale.getDefault())}</div>")
                }
                val cls = when (c.sev) { Sev.GOOD -> "good"; Sev.WARN -> "warn"; Sev.INFO -> "info" }
                val label = when (c.sev) { Sev.GOOD -> "正常"; Sev.WARN -> "警告"; Sev.INFO -> "提示" }
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
                putExtra(Intent.EXTRA_SUBJECT, "SecAudit 安全审计报告")
                putExtra(Intent.EXTRA_STREAM, uri)
                addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
            }
            startActivity(Intent.createChooser(send, "分享安全报告"))
        } catch (e: Exception) {
            Toast.makeText(this, "无法生成报告: ${e.message}", Toast.LENGTH_SHORT).show()
        }
    }

    private fun esc(s: String) = s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
}







