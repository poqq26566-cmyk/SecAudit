package com.test.secaudit

import android.content.Intent
import android.graphics.Color
import android.graphics.Typeface
import android.net.Uri
import android.os.Bundle
import android.provider.Settings
import android.view.Gravity
import android.view.View
import android.view.ViewGroup.LayoutParams.MATCH_PARENT
import android.view.ViewGroup.LayoutParams.WRAP_CONTENT
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import java.util.concurrent.Executors

/**
 * 专用界面：列出被标记为高风险（评分 >= 3）的应用及其原因
 * 并提供查看/卸载操作。后台扫描。
 */
class AppListActivity : BaseSecActivity() {

    private lateinit var container: LinearLayout
    private val amber = Color.parseColor("#F9A825")

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        container = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(px(18), px(22), px(18), px(28))
        }
        setContentView(ScrollView(this).apply { isFillViewport = true; addView(container) })

        container.addView(TextView(this).apply {
            text = "被标记的应用"
            textSize = 24f
            setTextColor(col(R.color.textPrimary))
            setTypeface(typeface, Typeface.BOLD)
        })
        val loading = TextView(this).apply {
            text = "正在分析应用…"
            textSize = 14f
            setTextColor(col(R.color.textSecondary))
            setPadding(0, px(16), 0, 0)
        }
        container.addView(loading)

        Executors.newSingleThreadExecutor().execute {
            val result = AppScanner.scan(this)
            runOnUiThread {
                if (isFinishing || isDestroyed) return@runOnUiThread
                container.removeView(loading)
                render(result)
            }
        }
    }

    private fun render(result: ScanResult) {
        container.addView(TextView(this).apply {
            text = if (result.flagged.isEmpty())
                "在 ${result.totalUserApps} 个用户应用中未发现可疑应用。"
            else
                "在 ${result.totalUserApps} 个用户应用中标记了 ${result.flagged.size} 个。请逐个审查；风险评分仅供参考，并非恶意软件判定。"
            textSize = 13f
            setTextColor(col(R.color.textSecondary))
            setPadding(0, px(6), 0, px(8))
        })

        for (app in result.flagged) {
            container.addView(buildAppCard(app), LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT).apply {
                topMargin = px(10)
            })
        }
    }

    private fun buildAppCard(app: AppRisk): View {
        val accent = if (app.high) col(R.color.warn) else amber
        val card = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            background = rounded(col(R.color.surface), px(16), accent and 0x55FFFFFF.toInt(), px(1))
            setPadding(px(16), px(14), px(16), px(14))
        }

        // 标题：应用名 + 风险等级
        card.addView(LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            addView(TextView(this@AppListActivity).apply {
                text = app.label
                textSize = 16f
                setTextColor(col(R.color.textPrimary))
                setTypeface(typeface, Typeface.BOLD)
            }, LinearLayout.LayoutParams(0, WRAP_CONTENT, 1f))
            addView(TextView(this@AppListActivity).apply {
                text = if (app.high) "高危" else "中危"
                textSize = 11f
                setTypeface(typeface, Typeface.BOLD)
                setTextColor(accent)
                background = rounded(accent and 0x22FFFFFF.toInt(), px(20))
                setPadding(px(12), px(5), px(12), px(5))
            })
        })
        card.addView(TextView(this).apply {
            text = app.pkg
            textSize = 11f
            setTextColor(col(R.color.textSecondary))
            setPadding(0, px(2), 0, px(8))
        })

        // 原因列表
        for (r in app.reasons) {
            card.addView(TextView(this).apply {
                text = "•  ${r.text}"
                textSize = 13f
                setTextColor(col(R.color.textSecondary))
                setLineSpacing(px(2).toFloat(), 1f)
                setPadding(0, px(2), 0, px(2))
            })
        }

        // 操作按钮
        card.addView(LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            setPadding(0, px(10), 0, 0)
            addView(makeButton("应用信息", filled = false) { openAppInfo(app.pkg) })
            addView(makeButton("卸载", filled = false) { uninstall(app.pkg) },
                LinearLayout.LayoutParams(WRAP_CONTENT, WRAP_CONTENT).apply { leftMargin = px(10) })
        })
        return card
    }

    private fun openAppInfo(pkg: String) = launchFirst(
        listOf(
            Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS, Uri.parse("package:$pkg")),
            Intent(Settings.ACTION_APPLICATION_SETTINGS)
        )
    )

    private fun uninstall(pkg: String) = launchFirst(
        listOf(Intent(Intent.ACTION_DELETE, Uri.parse("package:$pkg")))
    )
}
