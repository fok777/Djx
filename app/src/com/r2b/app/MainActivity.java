package com.r2b.app;

import android.app.Activity;
import android.app.AlertDialog;
import android.app.Dialog;
import android.content.Context;
import android.content.DialogInterface;
import android.content.Intent;
import android.os.Build;
import android.os.PowerManager;
import android.provider.Settings;
import android.content.res.ColorStateList;
import android.graphics.Color;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;
import android.net.Uri;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.util.Log;
import android.preference.PreferenceManager;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.widget.*;
import org.json.JSONArray;
import org.json.JSONObject;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.InputStream;
import java.util.List;
import java.util.ArrayList;

/**
 * Radare2Blutter MCP 安卓端主界面：
 * 主界面(logo+标题+远程服务/选APK按钮+文件框+日志) + 远程服务面板 + 工具列表弹窗(引擎卡片·点开展开)
 */
public class MainActivity extends Activity {
    LinearLayout mainView, svcView;
    TextView fileBox, logView, statusText;
    LinearLayout toolsRoot;
    Handler ui = new Handler(Looper.getMainLooper());
    McpService mcp;
    /** 本机工具执行器：点击工具直接真跑，不必依赖外部客户端。 */
    ToolExecutor toolExec;
    /** 服务日志回调（注册到 McpForegroundService）。 */
    final McpForegroundService.LogSink sink = new McpForegroundService.LogSink() {
        public void onLog(final String line) {
            appendLog(line);
        }
    };
    volatile boolean serverOn = false;

    @Override
    protected void onCreate(Bundle b) {
        super.onCreate(b);
        // 双保险：直接把窗口底色刷成浅色，避免任何深色模式残留
        getWindow().setBackgroundDrawable(new android.graphics.drawable.ColorDrawable(0xFFF5F7FA));
        int bg = 0xFFF5F7FA, card = 0xFFFFFFFF, txt = 0xFF202124, sub = 0xFF5F6368,
            blue = 0xFF1A73E8, green = 0xFF188038;
        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setBackgroundColor(bg);
        root.setPadding(dp(16), dp(16), dp(16), dp(16));

        // ===== 顶部 logo 行（圆蓝扳手 + 标题 + ⚙）=====
        LinearLayout top = new LinearLayout(this);
        top.setGravity(Gravity.CENTER_VERTICAL);
        TextView logo = iconCircle(0xFFD6E8FB, 0xFF1A73E8, "\uD83D\udd27", dp(56));
        LinearLayout tv = new LinearLayout(this);
        tv.setOrientation(LinearLayout.VERTICAL);
        TextView title = tv("Radare2Blutter MCP", 20, txt, true);
        TextView sub2 = tv("Flutter 逆向分析工具", 12, sub, false);
        tv.addView(title); tv.addView(sub2);
        LinearLayout.LayoutParams tlp = new LinearLayout.LayoutParams(0, -1, 1f);
        top.addView(logo); top.addView(tv, tlp);
        TextView gear = tv("⚙", 20, sub, false);
        top.addView(gear);
        root.addView(top, gap());

        // ===== 主界面 =====
        mainView = new LinearLayout(this);
        mainView.setOrientation(LinearLayout.VERTICAL);
        LinearLayout btnRow = new LinearLayout(this);
        Button remote = pill("R2B MCP 远程服务", 0xFFBDC7D5, txt);
        Button pick = pill("选择APK文件", 0xFF1A73E8, 0xFFFFFFFF);
        btnRow.addView(remote, weight(1f));
        btnRow.addView(pick, weight(1f));
        mainView.addView(btnRow, gap());
        fileBox = new TextView(this);
        fileBox.setText("未选择文件");
        fileBox.setTextColor(0xFF8A929E);
        fileBox.setSingleLine(true);
        fileBox.setPadding(dp(12), dp(12), dp(12), dp(12));
        fileBox.setBackground(roundRect(0xFFEEF1F5, dp(20)));
        mainView.addView(fileBox, gap());
        LinearLayout stRow = new LinearLayout(this);
        TextView ready = tv("就绪", 13, green, true);
        Button copyLog = pill("复制日志", 0xFFEEF1F5, blue);
        stRow.addView(ready, new LinearLayout.LayoutParams(0, -1, 1f));
        stRow.addView(copyLog);
        mainView.addView(stRow, gap());
        root.addView(mainView);

        // ===== 远程服务面板（默认隐藏）=====
        svcView = new LinearLayout(this);
        svcView.setOrientation(LinearLayout.VERTICAL);
        svcView.setVisibility(View.GONE);
        LinearLayout ctlRow = new LinearLayout(this);
        ctlRow.setGravity(Gravity.CENTER_VERTICAL);
        Button back = pill("返回", 0xFFEEF1F5, blue);
        ctlRow.addView(back);
        TextView ctl = tv("服务控制", 15, txt, true);
        statusText = tv("服务已停止", 14, 0xFF8A929E, true);
        ctlRow.addView(ctl, new LinearLayout.LayoutParams(0, -1, 1f));
        ctlRow.addView(statusText);
        svcView.addView(ctlRow, gap());
        svcView.addView(svcRow("本地", "http://127.0.0.1:5051/mcp"), gap());
        svcView.addView(svcRow("局域网", "http://" + lanIp() + ":5051/mcp"), gap());
        TextView rootOK = tv(rootStateText(), 13, hasRoot() ? green : 0xFF8A929E, false);
        svcView.addView(rootOK, gap());
        LinearLayout logBtnRow = new LinearLayout(this);
        Button toolListBtn = pill("工具列表", 0xFFEEF1F5, blue);
        Button copyAll = pill("复制全部", 0xFFEEF1F5, blue);
        logBtnRow.addView(toolListBtn);
        logBtnRow.addView(copyAll);
        logBtnRow.setGravity(Gravity.END);
        svcView.addView(logBtnRow, gap());
        logView = new TextView(this);
        int shownTotal = 0;
        JSONObject td0 = loadToolsData();
        if (td0 != null) shownTotal = td0.optInt("tool_total", 0);
        logView.setText("正在释放引擎资产…\n工具列表已构建：" + shownTotal + " 个工具\n"
            + "———— MCP 服务连接方式 Streamable HTTP ————\n"
            + "Radare2Blutter Mcp 服务启动在 0.0.0.0:5051 (LAN " + lanIp() + ")\n"
            + "———— Radare2Blutter Mcp 开始工作… ————");
        logView.setTextColor(0xFF5F6368);
        logView.setTextSize(12);
        logView.setTypeface(Typeface.MONOSPACE);
        logView.setPadding(dp(10), dp(10), 0, 0);
        svcView.addView(logView);
        root.addView(svcView);

        // ===== 按钮事件 =====
        remote.setOnClickListener(new View.OnClickListener() { public void onClick(View v) {
            mainView.setVisibility(View.GONE); svcView.setVisibility(View.VISIBLE);
            syncServiceState(); } });
        back.setOnClickListener(new View.OnClickListener() { public void onClick(View v) {
            svcView.setVisibility(View.GONE); mainView.setVisibility(View.VISIBLE); } });
        statusText.setOnClickListener(new View.OnClickListener() { public void onClick(View v) { toggleMcp(); } });
        pick.setOnClickListener(new View.OnClickListener() { public void onClick(View v) { Intent i = new Intent(Intent.ACTION_OPEN_DOCUMENT); i.addCategory(Intent.CATEGORY_OPENABLE); i.setType("*/*"); startActivityForResult(i, 101); } });
        toolListBtn.setOnClickListener(new View.OnClickListener() { public void onClick(View v) { showToolsDialog(); } });
        copyLog.setOnClickListener(new View.OnClickListener() { public void onClick(View v) { copyAll(); } });

        ScrollView sv = new ScrollView(this);
        sv.setBackgroundColor(bg);
        sv.setFillViewport(true);   // 内容不足一屏时也铺满，否则露出黑色 window 背景
        sv.addView(root);
        setContentView(sv);

        toolExec = new ToolExecutor(this);

        bindServiceLog();       // 接收前台服务的日志
        askTermuxPermission();  // Termux 通道：装了就能跑真实引擎
        syncServiceState();     // 与实际运行状态对齐（进程可能已被杀）
        askBatteryWhitelist();  // 引导加入电池优化白名单，否则后台易被杀
    }

    // ===== 工具列表弹窗（搜索 + 引擎卡片 + 点开展开工具）=====
    void showToolsDialog() {
        JSONObject data = loadToolsData();
        if (data == null) {
            new AlertDialog.Builder(this).setTitle("工具列表").setMessage("读取 tools_data.json 失败").show();
            return;
        }
        final int total = data.optInt("tool_total", 0);
        Dialog d = new Dialog(this, android.R.style.Theme_Light_NoTitleBar_Fullscreen);
        LinearLayout c = new LinearLayout(this);
        c.setOrientation(LinearLayout.VERTICAL);
        c.setBackgroundColor(0xFFF5F7FA);
        c.setPadding(dp(16), dp(12), dp(16), dp(16));

        // 标题栏
        LinearLayout head = new LinearLayout(this);
        head.setGravity(Gravity.CENTER_VERTICAL);
        head.addView(iconCircle(0xFFD6E8FB, 0xFF1A73E8, "\uD83D\udd27", dp(40)));
        LinearLayout ht = new LinearLayout(this); ht.setOrientation(LinearLayout.VERTICAL);
        ht.addView(tv("Radare2Blutter Mcp 工具列表", 17, 0xFF202124, true));
        final TextView cntView = tv("共 " + total + " 个工具 · 单击展开详情", 12, 0xFF8A929E, false);
        ht.addView(cntView);
        LinearLayout.LayoutParams hl = new LinearLayout.LayoutParams(0, -1, 1f);
        head.addView(ht, hl);
        Button close = pill("关闭", 0xFFEEF1F5, 0xFF1A73E8);
        head.addView(close);
        c.addView(head, gap());

        // 搜索框：工具多，必须能过滤
        final EditText search = new EditText(this);
        search.setHint("搜索工具名或说明…");
        search.setTextSize(14);
        search.setSingleLine(true);
        search.setPadding(dp(14), dp(10), dp(14), dp(10));
        search.setBackground(roundRect(0xFFFFFFFF, dp(12)));
        c.addView(search, gap());

        // 结果容器
        final LinearLayout listBox = new LinearLayout(this);
        listBox.setOrientation(LinearLayout.VERTICAL);

        // 预建所有卡片与工具行，后续靠 visibility 过滤
        final ArrayList<LinearLayout> cards = new ArrayList<LinearLayout>();
        final ArrayList<LinearLayout> lists = new ArrayList<LinearLayout>();
        final ArrayList<ArrayList<View>> rows = new ArrayList<ArrayList<View>>();
        final ArrayList<String> hay = new ArrayList<String>();
        final ArrayList<TextView> cntTx = new ArrayList<TextView>();

        JSONArray engines = data.optJSONArray("engines");
        if (engines == null) { new AlertDialog.Builder(this).setTitle("工具列表").setMessage("无引擎数据").show(); return; }
        for (int i = 0; i < engines.length(); i++) {
            JSONObject e = engines.optJSONObject(i);
            if (e == null) continue;
            final int color = Color.parseColor(e.optString("color", "#00897B"));
            String engName = e.optString("name");
            final LinearLayout card = new LinearLayout(this);
            card.setOrientation(LinearLayout.VERTICAL);
            card.setBackground(roundRect(0xFFFFFFFF, dp(16)));
            card.setPadding(dp(14), dp(12), dp(14), dp(12));
            card.setClickable(true);

            LinearLayout ch = new LinearLayout(this);
            ch.setGravity(Gravity.CENTER_VERTICAL);
            ch.addView(iconSquare(color, e.optString("icon", "\u2699"), dp(44)));
            LinearLayout cn = new LinearLayout(this); cn.setOrientation(LinearLayout.VERTICAL);
            cn.addView(tv(engName, 18, 0xFF202124, true));
            cn.addView(tv(e.optString("subtitle"), 12, 0xFF8A929E, false));
            ch.addView(cn, new LinearLayout.LayoutParams(0, -1, 1f));
            TextView cnt = tv(e.optInt("count") + " 个工具", 13, 0xFF1A73E8, true);
            ch.addView(cnt);
            card.addView(ch, gap());

            LinearLayout desc = new LinearLayout(this); desc.setOrientation(LinearLayout.VERTICAL);
            desc.addView(tv(e.optString("core"), 12, 0xFF5F6368, false));
            desc.addView(tv(e.optString("scene"), 12, 0xFF5F6368, false));
            desc.addView(tv(e.optString("flow"), 12, 0xFF5F6368, false));
            desc.addView(tv(e.optString("limit"), 12, 0xFF8A929E, false));
            card.addView(desc, gap());

            final LinearLayout tl = new LinearLayout(this);
            tl.setOrientation(LinearLayout.VERTICAL);
            tl.setVisibility(View.GONE);
            final ArrayList<View> rs = new ArrayList<View>();
            JSONArray tls = e.optJSONArray("tools");
            if (tls != null)
                for (int j = 0; j < tls.length(); j++) {
                    JSONObject t = tls.optJSONObject(j);
                    if (t == null) continue;
                    String nm = t.optString("name"), ds = t.optString("desc");
                    View r = toolRow(e.optString("icon", "\u2699"), color, engName, nm, ds);
                    r.setTag(engName + " " + nm + " " + ds);
                    final String toolName = nm;
                    r.setOnClickListener(new View.OnClickListener() {
                        public void onClick(View v) { runTool(toolName); }
                    });
                    rs.add(r);
                    tl.addView(r, gapS());
                }
            card.addView(tl, gap());
            card.setOnClickListener(new View.OnClickListener() { public void onClick(View v) {
                tl.setVisibility(tl.getVisibility() == View.VISIBLE ? View.GONE : View.VISIBLE); } });

            cards.add(card); lists.add(tl); rows.add(rs); hay.add(engName + " " + e.optString("subtitle"));
            cntTx.add(cnt);
            listBox.addView(card, gap());
        }
        c.addView(listBox);

        // ===== 底部分类图标条：点图标只显示该分类，再点取消 =====
        final HorizontalScrollView hsv = new HorizontalScrollView(this);
        hsv.setHorizontalScrollBarEnabled(false);
        LinearLayout tabs = new LinearLayout(this);
        tabs.setOrientation(LinearLayout.HORIZONTAL);
        tabs.setBackgroundColor(0xFFFFFFFF);
        tabs.setPadding(dp(8), dp(8), dp(8), dp(8));
        final ArrayList<TextView> tabViews = new ArrayList<TextView>();
        final int[] cur = {-1};   // -1 = 全部
        for (int i = 0; i < engines.length(); i++) {
            JSONObject e = engines.optJSONObject(i);
            if (e == null) continue;
            final int idx = i;
            final int color = Color.parseColor(e.optString("color", "#00897B"));
            TextView tb = iconSquare(color, e.optString("icon", "\u2699"), dp(46));
            tb.setTag(e.optString("name"));
            tb.setOnClickListener(new View.OnClickListener() { public void onClick(View v) {
                // 点图标直接弹出该分类的工具列表（可点、可真跑）
                showCategoryDialog(engines.optJSONObject(idx));
                cur[0] = (cur[0] == idx) ? -1 : idx;
                for (int k = 0; k < tabViews.size(); k++) {
                    tabViews.get(k).setAlpha(cur[0] == -1 ? 1.0f : (cur[0] == k ? 1.0f : 0.35f));
                }
                for (int k = 0; k < cards.size(); k++) {
                    cards.get(k).setVisibility(cur[0] == -1 || cur[0] == k ? View.VISIBLE : View.GONE);
                    lists.get(k).setVisibility(cur[0] == k ? View.VISIBLE : View.GONE);
                }
                search.setText("");
                String nm = cur[0] == -1 ? "" : String.valueOf(tabViews.get(cur[0]).getTag());
                cntView.setText(cur[0] == -1
                        ? ("共 " + total + " 个工具 · 单击展开详情")
                        : (nm + " · " + rows.get(cur[0]).size() + " 个工具"));
            } });
            tabViews.add(tb);
            LinearLayout.LayoutParams tp = new LinearLayout.LayoutParams(dp(46), dp(46));
            tp.rightMargin = dp(10);
            tabs.addView(tb, tp);
        }
        hsv.addView(tabs);
        c.addView(hsv);

        // 过滤逻辑
        search.addTextChangedListener(new android.text.TextWatcher() {
            public void beforeTextChanged(CharSequence s2, int a, int b, int c2) {}
            public void onTextChanged(CharSequence s2, int a, int b, int c2) {}
            public void afterTextChanged(android.text.Editable ed) {
                String q = ed.toString().trim().toLowerCase();
                if (q.length() > 0 && cur[0] != -1) {
                    cur[0] = -1;
                    for (int k = 0; k < tabViews.size(); k++) tabViews.get(k).setAlpha(1.0f);
                }
                int shown = 0, enginesShown = 0;
                for (int i = 0; i < cards.size(); i++) {
                    LinearLayout card = cards.get(i);
                    ArrayList<View> rs = rows.get(i);
                    int hit = 0;
                    for (View r : rs) {
                        String tag = String.valueOf(r.getTag()).toLowerCase();
                        boolean m = q.length() == 0 || tag.contains(q);
                        r.setVisibility(m ? View.VISIBLE : View.GONE);
                        if (m) hit++;
                    }
                    boolean engHit = q.length() > 0 && hay.get(i).toLowerCase().contains(q);
                    boolean vis = q.length() == 0 || hit > 0 || engHit;
                    card.setVisibility(vis ? View.VISIBLE : View.GONE);
                    if (vis) {
                        enginesShown++;
                        // 搜索时自动展开命中项，省掉手动点
                        lists.get(i).setVisibility(q.length() > 0 && hit > 0 ? View.VISIBLE : View.GONE);
                        cntTx.get(i).setText(q.length() > 0 ? (hit + " / " + rs.size() + " 命中") : (rs.size() + " 个工具"));
                    }
                    shown += hit;
                }
                cntView.setText(q.length() == 0
                        ? ("共 " + total + " 个工具 · 单击展开详情")
                        : ("匹配 " + shown + " 个工具 · " + enginesShown + " 个分类"));
            }
        });

        close.setOnClickListener(new View.OnClickListener() { public void onClick(View v) { d.dismiss(); } });

        ScrollView s2 = new ScrollView(this);
        s2.addView(c);
        d.setContentView(s2);
        d.show();
    }

    View toolRow(String eng, int color, String name, String desc) {
        return toolRow(eng, color, eng, name, desc);
    }

    View toolRow(String iconText, int color, String eng, String name, String desc) {
        LinearLayout r = new LinearLayout(this);
        r.setOrientation(LinearLayout.HORIZONTAL);
        r.setBackground(roundRect(0xFFF7F9FC, dp(12)));
        r.setPadding(dp(10), dp(8), dp(10), dp(8));
        r.setGravity(Gravity.CENTER_VERTICAL);
        TextView ic = iconSquare(color, iconText, dp(26));
        ic.setAlpha(0.75f);
        LinearLayout t = new LinearLayout(this); t.setOrientation(LinearLayout.VERTICAL);
        t.addView(tv(name, 14, 0xFF202124, true));
        t.addView(tv("【" + eng + "】" + desc, 11, 0xFF8A929E, false));
        LinearLayout.LayoutParams tlp = new LinearLayout.LayoutParams(0, -1, 1f);
        r.addView(ic); r.addView(t, tlp);
        return r;
    }

    /**
     * 点底部分类图标 -> 弹出该分类的工具列表，每行可点击真实执行。
     * 这是图标条真正该干的事：之前只做过滤，等于没有。
     */
    void showCategoryDialog(final JSONObject e) {
        if (e == null) return;
        String name = e.optString("name", "分类");
        int color = Color.parseColor(e.optString("color", "#00897B"));
        JSONArray tools = e.optJSONArray("tools");
        int n = tools == null ? 0 : tools.length();

        LinearLayout box = new LinearLayout(this);
        box.setOrientation(LinearLayout.VERTICAL);
        box.setPadding(dp(12), dp(10), dp(12), dp(10));

        if (n == 0) {
            TextView empty = tv("该分类没有工具数据", 13, 0xFF8A929E, false);
            box.addView(empty);
        } else {
            // 顶部：分类说明
            TextView head = tv(name + " · " + n + " 个工具", 15, 0xFF202124, true);
            box.addView(head, gapS());
            String sub = e.optString("subtitle", "");
            if (sub.length() > 0) {
                box.addView(tv(sub, 12, 0xFF5F6368, false), gapS());
            }

            ScrollView sv = new ScrollView(this);
            LinearLayout list = new LinearLayout(this);
            list.setOrientation(LinearLayout.VERTICAL);
            for (int i = 0; i < n; i++) {
                JSONObject t = tools.optJSONObject(i);
                if (t == null) continue;
                final String tn = t.optString("name", "");
                final String ds = t.optString("desc", "");
                View row = toolRow(e.optString("icon", "\u2699"), color, name, tn, ds);
                row.setOnClickListener(new View.OnClickListener() {
                    public void onClick(View v) { runTool(tn); }
                });
                list.addView(row, gapS());
            }
            sv.addView(list);
            box.addView(sv);
        }

        new AlertDialog.Builder(this)
            .setTitle(name)
            .setView(box)
            .setPositiveButton("关闭", null)
            .show();
    }

    /** 点击工具：本机真实执行并把结果展示出来。 */
    void runTool(final String toolName) {
        if (toolExec == null) toolExec = new ToolExecutor(this);
        appendLog("\u25b6 调用 " + toolName + " …");
        new Thread(new Runnable() { public void run() {
            String res;
            try {
                JSONObject args = new JSONObject();
                String apk = toolExec.getCurrentApk();
                if (apk != null) {
                    args.put("apk_path", apk);
                    args.put("path", apk);
                }
                res = toolExec.execute(toolName, args);
            } catch (Exception e) {
                res = "{\"error\": \"" + e.getMessage() + "\"}";
            }
            final String r = res;
            ui.post(new Runnable() { public void run() {
                appendLog("\u25c0 " + toolName + " 完成（" + r.length() + " 字符）");
                showResultDialog(toolName, r);
            } });
        } }).start();
    }

    /** 结果展示：可滚动、可复制。 */
    void showResultDialog(String title, String json) {
        String pretty = json;
        try {
            JSONObject o = new JSONObject(json);
            pretty = o.toString(2);
        } catch (Exception ignored) {
        }
        final String text = pretty;
        ScrollView sv = new ScrollView(this);
        TextView t = new TextView(this);
        t.setText(pretty);
        t.setTextSize(11);
        t.setTypeface(Typeface.MONOSPACE);
        t.setTextColor(0xFF202124);
        t.setTextIsSelectable(true);
        t.setPadding(dp(14), dp(14), dp(14), dp(14));
        sv.addView(t);
        android.content.ClipboardManager cm =
                (android.content.ClipboardManager) getSystemService(CLIPBOARD_SERVICE);
        new AlertDialog.Builder(this)
            .setTitle(title)
            .setView(sv)
            .setPositiveButton("关闭", null)
            .setNeutralButton("复制结果", new DialogInterface.OnClickListener() {
                public void onClick(DialogInterface d, int w) {
                    if (cm != null) cm.setPrimaryClip(
                            android.content.ClipData.newPlainText("r2b", text));
                }
            })
            .show();
    }

    boolean hasRoot() {
        String[] paths = {"/system/bin/su", "/system/xbin/su", "/sbin/su", "/su/bin/su"};
        for (String p : paths) if (new java.io.File(p).exists()) return true;
        return false;
    }

    String rootStateText() {
        if (hasRoot()) return "\u2713 Root (Frida 可用)";
        return "\u26a0 未 Root (Frida 不可用)";
    }

    String lanIp() {
        try {
            java.util.Enumeration<java.net.NetworkInterface> en =
                    java.net.NetworkInterface.getNetworkInterfaces();
            while (en.hasMoreElements()) {
                java.util.Enumeration<java.net.InetAddress> ia = en.nextElement().getInetAddresses();
                while (ia.hasMoreElements()) {
                    java.net.InetAddress a = ia.nextElement();
                    if (!a.isLoopbackAddress() && a instanceof java.net.Inet4Address)
                        return a.getHostAddress();
                }
            }
        } catch (Exception ignored) {}
        return "0.0.0.0";
    }

    JSONObject loadToolsData() {
        try {
            InputStream is = getAssets().open("tools_data.json");
            byte[] b = new byte[is.available()];
            is.read(b); is.close();
            return new JSONObject(new String(b, "UTF-8"));
        } catch (Exception e) { return null; }
    }

    // ===== 远程服务：应用内 MCP（Streamable HTTP，见 McpService）=====
    String loadToolsRaw() {
        try {
            InputStream is = getAssets().open("tools_data.json");
            ByteArrayOutputStream bo = new ByteArrayOutputStream();
            byte[] buf = new byte[8192];
            int n;
            while ((n = is.read(buf)) > 0) bo.write(buf, 0, n);
            is.close();
            return new String(bo.toByteArray(), "UTF-8");
        } catch (Exception e) {
            return "{}";
        }
    }

    /** 后台释放引擎资产；已在主线程外调用。 */
    void unpackEngines() {
        new Thread(new Runnable() { public void run() {
            try {
                final EngineUnpacker u = new EngineUnpacker(MainActivity.this,
                        new EngineUnpacker.Progress() {
                            public void onProgress(final String m) {
                                ui.post(new Runnable() { public void run() {
                                    if (logView != null) logView.append("\n" + m);
                                } });
                            }
                        });
                if (u.isUnpacked()) {
                    ui.post(new Runnable() { public void run() {
                        if (logView != null) logView.append("\n引擎已就绪\n" + EngineUnpacker.describe(MainActivity.this));
                    } });
                    return;
                }
                final int n = u.unpack();
                ui.post(new Runnable() { public void run() {
                    if (logView != null) logView.append("\n引擎释放完成：" + n + " 个文件\n"
                            + EngineUnpacker.describe(MainActivity.this));
                } });
            } catch (final Exception e) {
                ui.post(new Runnable() { public void run() {
                    if (logView != null) logView.append("\n引擎释放失败: " + e.getMessage());
                } });
            }
        } }).start();
    }

    /** 启动 MCP：交给前台 Service，Activity 销毁不影响服务。 */
    void startMcp() {
        Intent i = new Intent(this, McpForegroundService.class);
        i.setAction(McpForegroundService.ACTION_START);
        i.putExtra(McpForegroundService.EXTRA_PORT, 5051);
        i.putExtra(McpForegroundService.EXTRA_BACKEND, backendUrl());
        if (Build.VERSION.SDK_INT >= 26) {
            startForegroundService(i);
        } else {
            startService(i);
        }
        serverOn = true;
        statusText.setText("服务运行中");
        statusText.setTextColor(0xFF188038);
        statusText.setTag("stop");
        appendLog("已请求启动前台服务…");
        // 通知权限（Android 13+）：没权限通知不显示，服务仍能跑，但用户看不到状态
        if (Build.VERSION.SDK_INT >= 33
                && checkSelfPermission(android.Manifest.permission.POST_NOTIFICATIONS)
                        != android.content.pm.PackageManager.PERMISSION_GRANTED) {
            requestPermissions(
                    new String[]{android.Manifest.permission.POST_NOTIFICATIONS}, 201);
        }
    }

    void stopMcp() {
        Intent i = new Intent(this, McpForegroundService.class);
        i.setAction(McpForegroundService.ACTION_STOP);
        startService(i);
        serverOn = false;
        statusText.setText("服务已停止");
        statusText.setTextColor(0xFF8A929E);
        statusText.setTag(null);
        appendLog("已请求停止服务。");
    }

    String backendUrl() {
        return android.preference.PreferenceManager
                .getDefaultSharedPreferences(this).getString("backend_url", "");
    }

    /** 状态切换：点状态文字在 启/停 之间切换。 */
    void toggleMcp() {
        if (serverOn) stopMcp(); else startMcp();
    }

    void appendLog(final String line) {
        if (logView == null) return;
        ui.post(new Runnable() { public void run() {
            logView.append("\n" + line);
        } });
    }

    /** 注册服务日志回调；Activity 重建后先补历史日志。 */
    void bindServiceLog() {
        String hist = McpForegroundService.bufferedLog();
        if (hist != null && hist.length() > 0 && logView != null) {
            logView.append("\n[历史] " + hist.trim());
        }
        McpForegroundService.addSink(sink);
    }

    boolean isServiceUp() {
        // 通过端口探测判断是否真的在监听（比记标志位可靠：进程被杀后标志位会失真）
        try {
            java.net.Socket s = new java.net.Socket();
            s.connect(new java.net.InetSocketAddress("127.0.0.1", 5051), 300);
            s.close();
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    /** 进服务页时同步真实状态（进程可能已被杀或已在运行）。 */
    void syncServiceState() {
        new Thread(new Runnable() { public void run() {
            final boolean up = isServiceUp();
            ui.post(new Runnable() { public void run() {
                serverOn = up;
                if (up) {
                    statusText.setText("服务运行中");
                    statusText.setTextColor(0xFF188038);
                } else {
                    statusText.setText("服务已停止");
                    statusText.setTextColor(0xFF8A929E);
                }
            } });
        } }).start();
    }

    void copyAll() {
        try {
            String s = (logView != null ? logView.getText().toString() : "");
            android.content.ClipData c = android.content.ClipData.newPlainText("R2B", s);
            getSystemService(android.content.ClipboardManager.class);
            ((android.content.ClipboardManager) getSystemService(android.content.ClipboardManager.class))
                    .setPrimaryClip(c);
        } catch (Exception ignored) {}
    }

    // ===== 工具方法 =====
    TextView tv(String s, float sp, int c, boolean bold) {
        TextView t = new TextView(this);
        t.setText(s); t.setTextSize(sp); t.setTextColor(c);
        if (bold) t.setTypeface(Typeface.DEFAULT_BOLD);
        return t;
    }
    TextView iconCircle(int bg, int fg, String ch, int size) {
        TextView t = new TextView(this);
        t.setText(ch); t.setTextSize(size * 0.45f); t.setTextColor(fg);
        t.setGravity(Gravity.CENTER);
        GradientDrawable g = new GradientDrawable();
        g.setShape(GradientDrawable.OVAL); g.setColor(bg);
        t.setBackground(g);
        LinearLayout.LayoutParams p = new LinearLayout.LayoutParams(size, size);
        p.setMargins(0, 0, dp(10), 0);
        t.setLayoutParams(p);
        return t;
    }
    TextView iconSquare(int color, String ch, int size) {
        TextView t = new TextView(this);
        t.setText(ch); t.setTextSize(size * 0.4f); t.setTextColor(Color.WHITE);
        t.setGravity(Gravity.CENTER);
        GradientDrawable g = new GradientDrawable();
        g.setColor(color); g.setCornerRadius(dp(10));
        t.setBackground(g);
        LinearLayout.LayoutParams p = new LinearLayout.LayoutParams(size, size);
        p.setMargins(0, 0, dp(10), 0);
        t.setLayoutParams(p);
        return t;
    }
    Button pill(String s, int bg, int fg) {
        Button b = new Button(this);
        b.setText(s); b.setAllCaps(false);
        b.setGravity(Gravity.CENTER); b.setTextSize(13);
        b.setTextColor(fg);
        GradientDrawable g = new GradientDrawable();
        g.setColor(bg); g.setCornerRadius(dp(20));
        b.setBackground(g);
        return b;
    }
    LinearLayout svcRow(String label, String url) {
        LinearLayout r = new LinearLayout(this);
        r.setGravity(Gravity.CENTER_VERTICAL);
        TextView l = tv(label, 14, 0xFF5F6368, false);
        LinearLayout.LayoutParams ll = new LinearLayout.LayoutParams(dp(60), -1);
        r.addView(l, ll);
        TextView u = tv(url, 14, 0xFF202124, false);
        LinearLayout.LayoutParams ul = new LinearLayout.LayoutParams(0, -1, 1f);
        r.addView(u, ul);
        Button c = pill("复制", 0xFFEEF1F5, 0xFF1A73E8);
        r.addView(c);
        return r;
    }
    GradientDrawable roundRect(int color, int r) {
        GradientDrawable g = new GradientDrawable();
        g.setColor(color); g.setCornerRadius(r);
        return g;
    }
    LinearLayout.LayoutParams gap() {
        LinearLayout.LayoutParams p = new LinearLayout.LayoutParams(-1, -2);
        p.bottomMargin = dp(12);
        return p;
    }
    LinearLayout.LayoutParams gapS() {
        LinearLayout.LayoutParams p = new LinearLayout.LayoutParams(-1, -2);
        p.bottomMargin = dp(6);
        return p;
    }
    // weight 必须为正数：LinearLayout 在 totalWeight<=0 时不分配剩余空间，
    // 而 width=0 的子 View 就只能得到 0 宽度（按钮会整个消失）。
    // 高度用 WRAP_CONTENT(-2)，不能用 MATCH_PARENT(-1)。
    LinearLayout.LayoutParams weight(float w) {
        LinearLayout.LayoutParams p = new LinearLayout.LayoutParams(0, -2, w);
        p.rightMargin = dp(8);
        return p;
    }
    int dp(int d) { return (int) (d * getResources().getDisplayMetrics().density); }

    /** Activity 销毁：只解绑日志回调，绝不杀服务（服务独立存活）。 */
    @Override
    protected void onDestroy() {
        McpForegroundService.removeSink(sink);
        super.onDestroy();
        Log.i("R2B", "Activity 销毁，MCP 服务继续运行");
    }

    /** 回到前台时同步真实状态。 */
    @Override
    protected void onResume() {
        super.onResume();
        if (svcView != null && svcView.getVisibility() == View.VISIBLE) syncServiceState();
    }

    /** 把 SAF 选中的 Uri 尽量转成可直接访问的路径。 */
    String resolvePickedPath(Uri uri, String display) {
        // 1) 先试常见公开目录（Download 等）
        String name = null;
        if (display != null && display.length() > 0) {
            name = display;
            if (name.startsWith("primary:")) name = name.substring(8);
            int i = name.lastIndexOf('/');
            if (i >= 0) name = name.substring(i + 1);
        }
        if (name != null) {
            File[] dirs = {
                android.os.Environment.getExternalStoragePublicDirectory(
                        android.os.Environment.DIRECTORY_DOWNLOADS),
                new File("/sdcard/Download"),
                new File("/sdcard/Downloads"),
            };
            for (File d : dirs) {
                if (d == null) continue;
                File c = new File(d, name);
                if (c.exists() && c.isFile()) return c.getAbsolutePath();
            }
        }
        // 2) 拷到私有目录，保证一定能读
        try {
            java.io.InputStream is = getContentResolver().openInputStream(uri);
            if (is == null) return null;
            File out = new File(getCacheDir(), "picked.apk");
            java.io.FileOutputStream os = new java.io.FileOutputStream(out);
            byte[] buf = new byte[65536];
            int r;
            while ((r = is.read(buf)) > 0) os.write(buf, 0, r);
            os.close(); is.close();
            return out.getAbsolutePath();
        } catch (Exception e) {
            return null;
        }
    }

    /** Termux 授权：装了 Termux 就申请 RUN_COMMAND 权限，让工具能真跑。 */
    void askTermuxPermission() {
        if (toolExec == null) toolExec = new ToolExecutor(this);
        TermuxExecutor tx = toolExec.termux();
        if (!tx.installed()) {
            appendLog("未检测到 Termux，工具将只用内置 Java 引擎（能力有限）");
            return;
        }
        if (tx.hasPermission()) {
            appendLog("Termux 通道就绪");
            return;
        }
        new AlertDialog.Builder(this)
            .setTitle("启用 Termux 通道")
            .setMessage("检测到已安装 Termux。授予 RUN_COMMAND 权限后，"
                    + "工具可执行真实的 radare2 / blutter / frida / unidbg，"
                    + "能力远超内置解析。\n\n"
                    + "若授权后仍失败，需在 Termux 里执行：\n"
                    + "echo allow-external-apps=true >> ~/.termux/termux.properties")
            .setPositiveButton("授权", new DialogInterface.OnClickListener() {
                public void onClick(DialogInterface d, int w) {
                    if (Build.VERSION.SDK_INT >= 23) {
                        requestPermissions(new String[]{TermuxExecutor.PERMISSION}, 202);
                    }
                }
            })
            .setNegativeButton("暂不", null)
            .show();
    }

    @Override
    public void onRequestPermissionsResult(int code, String[] perms, int[] res) {
        super.onRequestPermissionsResult(code, perms, res);
        if (code == 202 && res.length > 0
                && res[0] == android.content.pm.PackageManager.PERMISSION_GRANTED) {
            appendLog("Termux 权限已授予");
            // 探测装了哪些真实引擎
            new Thread(new Runnable() { public void run() {
                if (toolExec == null) return;
                final String p = toolExec.termux().probe();
                ui.post(new Runnable() { public void run() { appendLog("引擎探测: " + p); } });
            } }).start();
        }
    }

    /** 电池优化白名单：不加入的话系统会在几分钟内杀掉后台服务。 */
    void askBatteryWhitelist() {
        if (Build.VERSION.SDK_INT < 23) return;
        PowerManager pm = (PowerManager) getSystemService(Context.POWER_SERVICE);
        if (pm == null || pm.isIgnoringBatteryOptimizations(getPackageName())) return;
        new AlertDialog.Builder(this)
            .setTitle("保持服务运行")
            .setMessage("MCP 服务需要在后台持续运行。\n"
                    + "若不加入电池优化白名单，系统会在几分钟后杀掉服务，"
                    + "表现为“挂着挂着就没了”。")
            .setPositiveButton("去设置", new DialogInterface.OnClickListener() {
                public void onClick(DialogInterface d, int w) {
                    try {
                        Intent i = new Intent(
                                Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS);
                        i.setData(Uri.parse("package:" + getPackageName()));
                        startActivity(i);
                    } catch (Exception e) {
                        appendLog("无法打开电池优化设置: " + e.getMessage());
                    }
                }
            })
            .setNegativeButton("暂不", null)
            .show();
    }

    @Override
    protected void onActivityResult(int req, int res, Intent data) {
        super.onActivityResult(req, res, data);
        // 选完 APK 立刻同步：工具调用会用它作为默认输入
        if (req == 101 && res == RESULT_OK && data != null && data.getData() != null && fileBox != null) {
            String shown = fileBox.getText() == null ? "" : fileBox.getText().toString();
            String real = resolvePickedPath(data.getData(), shown);
            if (real != null) {
                if (toolExec == null) toolExec = new ToolExecutor(this);
                toolExec.setCurrentApk(real);
                McpForegroundService.pushApkToService(real);
                appendLog("已选择 APK: " + real);
            }
        }
        if (req == 101 && res == RESULT_OK && data != null && data.getData() != null) {
            fileBox.setText(data.getData().getLastPathSegment());
            fileBox.setTextColor(0xFF1A73E8);
            if (logView != null) logView.append("\n[APK] 已选 " + data.getData() + "，将由 r2b_apk_open 处理");
        }
    }
}
