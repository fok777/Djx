package com.r2b.app;

import android.content.Context;
import android.graphics.Color;
import android.graphics.Typeface;
import android.text.ClipboardManager;
import android.util.TypedValue;
import android.view.Gravity;
import android.view.View;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

import java.io.File;
import java.util.List;

/**
 * APK 分析结果卡片：选完文件直接内联展示在主界面。
 *
 * 之前的问题：选完 APK 只在服务日志里打一行，主界面毫无反应——
 * 用户根本不知道发生了什么。这里把关键结论直接画出来：
 *   技术栈（Flutter / Unity / RN / 原生）
 *   包名、版本、大小
 *   native so 清单与架构
 *   权限、组件统计
 * 并给出下一步可点的动作（分析 so / 提取符号 / 查字符串）。
 */
public final class ApkResultCard {

    public interface ActionListener {
        void onAction(String action, String arg);
    }

    private ApkResultCard() {}

    /** 把分析结果渲染进容器。 */
    public static void render(Context c, LinearLayout card, final NativeAnalyzer.ApkInfo info,
                              final File apk, final ActionListener l) {
        card.removeAllViews();
        if (info == null) {
            card.setVisibility(View.GONE);
            return;
        }
        card.setVisibility(View.VISIBLE);

        if (info.error != null) {
            card.addView(section(c, "解析失败", info.error, 0xFFC5221F));
            return;
        }

        // ---- 技术栈 ----
        String stack;
        int stackColor;
        if (info.hasFlutter)      { stack = "Flutter / Dart"; stackColor = 0xFF1A73E8; }
        else if (info.hasIl2Cpp)  { stack = "Unity / IL2CPP"; stackColor = 0xFF8E24AA; }
        else if (info.hasReactNative) { stack = "React Native"; stackColor = 0xFF0288D1; }
        else                      { stack = "原生 Java/Kotlin"; stackColor = 0xFF00897B; }

        TextView tag = new TextView(c);
        tag.setText(stack);
        tag.setTextColor(0xFFFFFFFF);
        tag.setTextSize(TypedValue.COMPLEX_UNIT_SP, 13);
        tag.setTypeface(null, Typeface.BOLD);
        tag.setGravity(Gravity.CENTER);
        int pd = dp(c, 10);
        tag.setPadding(pd, dp(c, 6), pd, dp(c, 6));
        tag.setBackground(roundRect(stackColor, dp(c, 16)));
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(-2, -2);
        lp.gravity = Gravity.CENTER_HORIZONTAL;
        card.addView(tag, lp);
        card.addView(space(c, 10));

        // ---- 基本信息 ----
        StringBuilder b = new StringBuilder();
        b.append("文件：").append(apk == null ? "-" : apk.getName()).append('\n');
        b.append("大小：").append(human(info.size)).append('\n');
        b.append("条目：").append(info.entries.size()).append(" 个\n");
        b.append("DEX ：").append(info.dexes.size()).append(" 个");
        if (!info.dexes.isEmpty()) b.append(" (").append(join(info.dexes, ", ")).append(')');
        b.append('\n');
        b.append("架构：").append(info.archs.isEmpty() ? "无 native" : join(info.archs, ", "));
        card.addView(section(c, "基本信息", b.toString(), 0xFF202124));

        // ---- native so ----
        if (!info.libs.isEmpty()) {
            StringBuilder sb = new StringBuilder();
            int n = Math.min(info.libs.size(), 12);
            for (int i = 0; i < n; i++) sb.append("• ").append(info.libs.get(i)).append('\n');
            if (info.libs.size() > n) {
                sb.append("… 其余 ").append(info.libs.size() - n).append(" 个");
            }
            card.addView(section(c, "Native 库（" + info.libs.size() + "）",
                    sb.toString().trim(), 0xFF202124));
        }

        // ---- 下一步动作 ----
        LinearLayout acts = new LinearLayout(c);
        acts.setOrientation(LinearLayout.HORIZONTAL);
        acts.setGravity(Gravity.CENTER);
        if (!info.libs.isEmpty()) {
            acts.addView(actionBtn(c, "分析 SO", new View.OnClickListener() {
                public void onClick(View v) {
                    if (l != null) l.onAction("analyze_so",
                            info.libs.isEmpty() ? "" : info.libs.get(0));
                }
            }));
        }
        acts.addView(actionBtn(c, "提取字符串", new View.OnClickListener() {
            public void onClick(View v) { if (l != null) l.onAction("strings", ""); }
        }));
        acts.addView(actionBtn(c, "复制链接", new View.OnClickListener() {
            public void onClick(View v) {
                ClipboardManager cm = (ClipboardManager) c.getSystemService(Context.CLIPBOARD_SERVICE);
                if (cm != null) cm.setText(apk == null ? "" : apk.getAbsolutePath());
            }
        }));
        card.addView(acts, space(c, 4));
    }

    /** 展示任意一段分析结果（用于后续工具结果的回显）。 */
    public static void showResult(Context c, LinearLayout card, String title, String body) {
        card.removeAllViews();
        card.setVisibility(View.VISIBLE);
        card.addView(section(c, title, body, 0xFF202124));
    }

    // ---------- 内部控件 ----------

    private static View section(Context c, String title, String body, int bodyColor) {
        LinearLayout box = new LinearLayout(c);
        box.setOrientation(LinearLayout.VERTICAL);
        box.setBackground(roundRect(0xFFFFFFFF, dp(c, 12)));
        int p = dp(c, 12);
        box.setPadding(p, p, p, p);

        TextView t = new TextView(c);
        t.setText(title);
        t.setTextColor(0xFF5F6368);
        t.setTextSize(TypedValue.COMPLEX_UNIT_SP, 11.5f);
        t.setTypeface(null, Typeface.BOLD);
        box.addView(t);

        TextView v = new TextView(c);
        v.setText(body);
        v.setTextColor(bodyColor);
        v.setTextSize(TypedValue.COMPLEX_UNIT_SP, 12.5f);
        v.setTypeface(Typeface.MONOSPACE);
        v.setPadding(0, dp(c, 5), 0, 0);
        v.setTextIsSelectable(true);
        box.addView(v);

        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(-1, -2);
        lp.bottomMargin = dp(c, 8);
        box.setLayoutParams(lp);
        return box;
    }

    private static TextView actionBtn(Context c, String label, View.OnClickListener l) {
        TextView t = new TextView(c);
        t.setText(label);
        t.setTextColor(0xFF1A73E8);
        t.setTextSize(TypedValue.COMPLEX_UNIT_SP, 12.5f);
        t.setTypeface(null, Typeface.BOLD);
        t.setGravity(Gravity.CENTER);
        int pd = dp(c, 10);
        t.setPadding(pd, dp(c, 7), pd, dp(c, 7));
        t.setBackground(roundRect(0xFFEEF1F5, dp(c, 16)));
        t.setOnClickListener(l);
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(-2, -2);
        lp.rightMargin = dp(c, 8);
        t.setLayoutParams(lp);
        return t;
    }

    private static View space(Context c, int d) {
        View v = new View(c);
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(-1, dp(c, d));
        v.setLayoutParams(lp);
        return v;
    }

    private static android.graphics.drawable.Drawable roundRect(int color, int radius) {
        android.graphics.drawable.GradientDrawable d =
                new android.graphics.drawable.GradientDrawable();
        d.setColor(color);
        d.setCornerRadius(radius);
        return d;
    }

    private static int dp(Context c, int v) {
        return (int) TypedValue.applyDimension(TypedValue.COMPLEX_UNIT_DIP, v,
                c.getResources().getDisplayMetrics());
    }

    private static String human(long bytes) {
        if (bytes < 1024) return bytes + " B";
        if (bytes < 1048576) return String.format("%.1f KB", bytes / 1024.0);
        return String.format("%.1f MB", bytes / 1048576.0);
    }

    private static String join(List<String> l, String sep) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < l.size(); i++) {
            if (i > 0) sb.append(sep);
            sb.append(l.get(i));
        }
        return sb.toString();
    }
}
