package com.test.secaudit

import android.graphics.Color
import android.graphics.Typeface
import android.graphics.drawable.GradientDrawable
import android.view.Gravity
import android.view.View
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat

enum class Sev { GOOD, WARN, INFO }

/**
 * 包含 UI 辅助方法的基类（深色风格，无 XML），供 MainActivity 和 AppListActivity 复用：
 * dp→px 转换、颜色、圆角背景和按钮。
 */
abstract class BaseSecActivity : AppCompatActivity() {

    protected val density by lazy { resources.displayMetrics.density }
    protected fun px(v: Int) = (v * density).toInt()

    protected fun col(id: Int) = ContextCompat.getColor(this, id)

    protected fun sevColor(s: Sev) = when (s) {
        Sev.GOOD -> col(R.color.good)
        Sev.WARN -> col(R.color.warn)
        Sev.INFO -> col(R.color.info)
    }

    protected fun rounded(fill: Int, radius: Int, strokeColor: Int = 0, strokeW: Int = 0) =
        GradientDrawable().apply {
            setColor(fill)
            cornerRadius = radius.toFloat()
            if (strokeW > 0) setStroke(strokeW, strokeColor)
        }

    /** 样式化按钮（无 XML）：填充色或描边。 */
    protected fun makeButton(label: String, filled: Boolean, onClick: () -> Unit): View =
        TextView(this).apply {
            text = label
            textSize = 14f
            gravity = Gravity.CENTER
            setTypeface(typeface, Typeface.BOLD)
            isClickable = true
            setPadding(px(20), px(12), px(20), px(12))
            if (filled) {
                setTextColor(Color.parseColor("#0D1117"))
                background = rounded(col(R.color.accent), px(12))
            } else {
                setTextColor(col(R.color.accent))
                background = rounded(Color.TRANSPARENT, px(12), col(R.color.accent), px(1))
            }
            setOnClickListener { onClick() }
        }

    /** 启动第一个可解析的 Intent；如果都失败则回退到通用设置。 */
    protected fun launchFirst(candidates: List<android.content.Intent>) {
        for (i in candidates) {
            try { startActivity(i); return } catch (_: Exception) { /* 尝试下一个 */ }
        }
        try { startActivity(android.content.Intent(android.provider.Settings.ACTION_SETTINGS)) } catch (_: Exception) {}
    }
}
