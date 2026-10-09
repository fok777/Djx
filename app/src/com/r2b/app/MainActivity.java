package com.r2b.app;

import android.app.Activity;
import android.app.AlertDialog;
import android.app.Dialog;
import android.content.Context;
import android.content.ClipboardManager;
import android.content.ClipData;
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
import android.widget.EditText;
import android.widget.ScrollView;
import android.widget.TextView;
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
    /** 选完 APK 后的分析结果卡片（内联在主界面，不用切到服务页看日志）。 */
    LinearLayout apkCard;
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
        TextView gear = tv("\u2699", 20, sub, false);
        gear.setPadding(dp(8), dp(4), dp(8), dp(4));
        gear.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) { showSettings(); }
        });
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
        Button viewLog = pill("查看日志", 0xFFEEF1F5, blue);
        Button copyLog = pill("复制日志", 0xFFEEF1F5, blue);
        stRow.addView(ready, new LinearLayout.LayoutParams(0, -1, 1f));
        stRow.addView(viewLog);
        stRow.addView(copyLog);
        mainView.addView(stRow, gap());
        // APK 分析结果：选完文件直接在这里出，不再只往服务日志里打
        apkCard = new LinearLayout(this);
        apkCard.setOrientation(LinearLayout.VERTICAL);
        apkCard.setVisibility(View.GONE);
        mainView.addView(apkCard, gap());
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
        // 长按直接选中日志，不依赖剪贴板
        logView.setTextIsSelectable(true);
        logView.setFocusable(true);
        logView.setFocusableInTouchMode(true);
        svcView.addView(logView);
        root.addView(svcView);

        // ===== 打开即自动启动 MCP 服务（黑猫原版行为）=====
        // 用户不需要手动点"远程服务"再点启动——进 App 服务就该在跑。
        // 用 SharedPreferences 记住开关，设置里可关。
        if (android.preference.PreferenceManager.getDefaultSharedPreferences(this)
                .getBoolean("auto_start_service", true)) {
            autoStartMcp();
        }

        // ===== 按钮事件 =====
        remote.setOnClickListener(new View.OnClickListener() { public void onClick(View v) {
            mainView.setVisibility(View.GONE); svcView.setVisibility(View.VISIBLE);
            syncServiceState(); } });
        back.setOnClickListener(new View.OnClickListener() { public void onClick(View v) {
            svcView.setVisibility(View.GONE); mainView.setVisibility(View.VISIBLE); } });
        statusText.setOnClickListener(new View.OnClickListener() { public void onClick(View v) { toggleMcp(); } });
        pick.setOnClickListener(new View.OnClickListener() { public void onClick(View v) { Intent i = new Intent(Intent.ACTION_OPEN_DOCUMENT); i.addCategory(Intent.CATEGORY_OPENABLE); i.setType("*/*"); startActivityForResult(i, 101); } });
        toolListBtn.setOnClickListener(new View.OnClickListener() { public void onClick(View v) { showToolsDialog(); } });
        // 服务页这个 copyAll 是独立对象，之前完全没绑事件
        copyAll.setOnClickListener(new View.OnClickListener() { public void onClick(View v) { copyAll(); } });
        copyLog.setOnClickListener(new View.OnClickListener() { public void onClick(View v) { copyAll(); } });
        viewLog.setOnClickListener(new View.OnClickListener() { public void onClick(View v) {
            String c = collectAllLog();
            if (c.isEmpty()) { toast("暂无日志"); return; }
            showLogViewDialog(c, "共 " + c.length() + " 字符");
        } });

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
                    final JSONObject toolObj = t;
                    r.setOnClickListener(new View.OnClickListener() {
                        public void onClick(View v) { showToolForm(toolObj); }
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
    /**
     * 点工具后先弹参数表单（有参数时），填完再执行。
     * 之前只能自动塞 apk_path，R2_/Blutter_ 这类需要路径/地址的工具根本没法用。
     */
    void showToolForm(final JSONObject tool) {
        final String name = tool.optString("name");
        JSONArray params = tool.optJSONArray("params");
        if (params == null || params.length() == 0) {
            runTool(name, new JSONObject());
            return;
        }
        // 先预填能推断的值，减少手工输入
        final JSONObject preset = new JSONObject();
        try {
            String apk = toolExec == null ? null : toolExec.getCurrentApk();
            for (int i = 0; i < params.length(); i++) {
                JSONObject p = params.optJSONObject(i);
                if (p == null) continue;
                String pn = p.optString("name");
                if (apk != null && (pn.equals("apk_path") || pn.equals("path")
                        || pn.equals("apk") || pn.equals("file"))) {
                    preset.put(pn, apk);
                }
            }
        } catch (Exception ignored) {}

        android.app.AlertDialog.Builder b = new android.app.AlertDialog.Builder(this);
        b.setTitle(name);
        LinearLayout box = new LinearLayout(this);
        box.setOrientation(LinearLayout.VERTICAL);
        box.setPadding(dp(18), dp(10), dp(18), dp(4));
        final ArrayList<EditText> inputs = new ArrayList<EditText>();
        final ArrayList<String> keys = new ArrayList<String>();
        for (int i = 0; i < params.length(); i++) {
            JSONObject p = params.optJSONObject(i);
            if (p == null) continue;
            String pn = p.optString("name");
            String pd = p.optString("desc");
            boolean req = p.optBoolean("required");
            TextView lab = new TextView(this);
            lab.setText(pn + (req ? " *" : "") + (pd.isEmpty() ? "" : "  (" + pd + ")"));
            lab.setTextSize(12);
            lab.setTextColor(req ? 0xFFC5221F : 0xFF5F6368);
            box.addView(lab);
            final EditText et = new EditText(this);
            et.setText(preset.optString(pn, ""));
            et.setSingleLine(true);
            et.setTextSize(13);
            et.setPadding(dp(10), dp(8), dp(10), dp(8));
            box.addView(et);
            inputs.add(et);
            keys.add(pn);
        }
        android.widget.ScrollView sv = new android.widget.ScrollView(this);
        sv.addView(box);
        b.setView(sv);
        b.setNegativeButton("取消", null);
        b.setPositiveButton("执行", new android.content.DialogInterface.OnClickListener() {
            public void onClick(android.content.DialogInterface dlg, int w) {
                JSONObject args = new JSONObject();
                for (int i = 0; i < inputs.size(); i++) {
                    String v = inputs.get(i).getText() == null ? ""
                            : inputs.get(i).getText().toString().trim();
                    if (v.isEmpty()) continue;
                    try { args.put(keys.get(i), v); } catch (Exception ignored) {}
                }
                runTool(name, args);
            }
        });
        b.show();
    }

    void runTool(final String toolName) { runTool(toolName, new JSONObject()); }

    void runTool(final String toolName, final JSONObject userArgs) {
        if (toolExec == null) toolExec = new ToolExecutor(this);
        appendLog("\u25b6 调用 " + toolName + " …");
        new Thread(new Runnable() { public void run() {
            String res;
            try {
                JSONObject args = new JSONObject();
                try {
                    java.util.Iterator<String> it = userArgs.keys();
                    while (it.hasNext()) {
                        String k = it.next();
                        args.put(k, userArgs.get(k));
                    }
                } catch (Exception ignored) {}
                String apk = toolExec.getCurrentApk();
                if (apk != null) {
                    if (!args.has("apk_path")) args.put("apk_path", apk);
                    if (!args.has("path")) args.put("path", apk);
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
                if (EngineUnpacker.isUnpacked(MainActivity.this)) {
                    ui.post(new Runnable() { public void run() {
                        if (logView != null) logView.append("\n引擎已就绪\n" + EngineUnpacker.describe(MainActivity.this));
                    } });
                    return;
                }
                ui.post(new Runnable() { public void run() {
                    if (logView != null) logView.append("\n开始释放只读引擎数据…");
                } });
                final int n = EngineUnpacker.unpackAssets(MainActivity.this);
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

    /** 完整日志缓冲：复制时用它，而不是只读可见的 logView。 */
    private final StringBuilder fullLog = new StringBuilder();

    void appendLog(final String line) {
        if (line == null) return;
        // 带时间戳，和黑猫日志格式一致，便于对照时间线排查
        String ts = new java.text.SimpleDateFormat("[HH:mm:ss]",
                java.util.Locale.US).format(new java.util.Date());
        fullLog.append("\n").append(ts).append(" ").append(line);
        if (logView == null) return;
        final String shown = ts + " " + line;
        ui.post(new Runnable() { public void run() {
            logView.append("\n" + shown);
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

    /**
     * 复制日志。
     *
     * 之前"复制没卵用"的三个原因：
     *   1. 异常被 catch 后 ignored，失败了也不知道
     *   2. 没有成功反馈，点了没反应
     *   3. 日志很长时部分 ROM 的剪贴板会静默失败
     * 现在：给 Toast 反馈；失败时改存文件并把路径显示出来。
     */
    /**
     * 设置弹窗：文件导出路径 + 自动启动服务开关。
     * 旧版就有"文件导出路径"这一项，分析结果需要落盘到用户能找到的地方。
     */
    void showSettings() {
        final android.app.AlertDialog.Builder b =
                new android.app.AlertDialog.Builder(this);
        LinearLayout box = new LinearLayout(this);
        box.setOrientation(LinearLayout.VERTICAL);
        box.setPadding(dp(20), dp(14), dp(20), dp(6));

        TextView t = tv("\u2699 设置", 16, 0xFF202124, true);
        box.addView(t);

        // ---- 文件导出路径 ----
        box.addView(tv("文件导出路径", 12, 0xFF5F6368, true));
        final TextView pathView = new TextView(this);
        final String[] curPath = {exportDir().getAbsolutePath()};
        pathView.setText(curPath[0]);
        pathView.setTextSize(12);
        pathView.setTextColor(0xFF1A73E8);
        pathView.setPadding(0, dp(4), 0, dp(6));
        box.addView(pathView);

        Button pickDir = pill("选择目录", 0xFF1A73E8, 0xFFFFFFFF);
        pickDir.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) {
                try {
                    Intent i = new Intent(Intent.ACTION_OPEN_DOCUMENT_TREE);
                    i.putExtra("android.content.extra.SHOW_ADVANCED", true);
                    startActivityForResult(i, 102);
                } catch (Exception e) {
                    toast("无法打开目录选择器: " + e.getMessage());
                }
            }
        });
        box.addView(pickDir, gap());

        // ---- 自动启动服务 ----
        final android.widget.CheckBox cb = new android.widget.CheckBox(this);
        cb.setText("打开 App 时自动启动 MCP 服务");
        cb.setTextSize(13);
        cb.setChecked(android.preference.PreferenceManager
                .getDefaultSharedPreferences(this)
                .getBoolean("auto_start_service", true));
        box.addView(cb);

        final android.widget.CheckBox cbRoot = new android.widget.CheckBox(this);
        cbRoot.setText("尝试以 Root 拉起 frida-server");
        cbRoot.setTextSize(13);
        cbRoot.setChecked(android.preference.PreferenceManager
                .getDefaultSharedPreferences(this)
                .getBoolean("auto_frida", false));
        box.addView(cbRoot);

        Button save = pill("保存配置", 0xFF188038, 0xFFFFFFFF);
        box.addView(save, gap());

        android.widget.ScrollView sv = new android.widget.ScrollView(this);
        sv.addView(box);
        b.setView(sv);
        final android.app.AlertDialog dlg = b.create();
        // 保存后关闭
        save.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) {
                android.preference.PreferenceManager.getDefaultSharedPreferences(
                        MainActivity.this).edit()
                        .putString("export_dir", curPath[0])
                        .putBoolean("auto_start_service", cb.isChecked())
                        .putBoolean("auto_frida", cbRoot.isChecked())
                        .apply();
                toast("配置已保存");
                appendLog("导出路径: " + curPath[0]);
                // 勾了自动启动且当前没跑，立刻起
                if (cb.isChecked() && !McpForegroundService.isRunning()) {
                    startMcp();
                }
                dlg.dismiss();
            }
        });
        dlg.show();
    }

    /** 分析结果导出目录。默认放在公共 Download 下，方便取出。 */
    File exportDir() {
        String saved = android.preference.PreferenceManager
                .getDefaultSharedPreferences(this).getString("export_dir", "");
        if (saved != null && !saved.isEmpty()) return new File(saved);
        File d = new File(android.os.Environment
                .getExternalStoragePublicDirectory(
                        android.os.Environment.DIRECTORY_DOWNLOADS),
                "Flutter分析结果");
        if (!d.exists()) d.mkdirs();
        return d;
    }

    /**
     * 打开 App 就自动把 MCP 服务拉起来。
     * 延迟 300ms：等首帧绘制完，避免和 UI 抢资源导致卡顿。
     */
    void autoStartMcp() {
        ui.postDelayed(new Runnable() { public void run() {
            if (McpForegroundService.isRunning()) {
                appendLog("MCP 服务已在运行");
                return;
            }
            appendLog("自动启动 MCP 服务…");
            startMcp();
        } }, 300);
    }

    /**
     * 复制日志。
     *
     * 之前"点了没反应"的原因有两个：
     *   1. 只取 logView 的文本——主界面上 logView 属于隐藏的服务面板，
     *      内容可能是空的或过时的
     *   2. setPrimaryClip 在部分 ROM 上静默失败，没有任何提示
     *
     * 现在：优先用完整缓冲 fullLog（无论当前在哪一页都完整），
     * 复制同时**一定**写一份到导出目录，并在 Toast 里给出路径——
     * 剪贴板靠不住时用户至少有文件可拿。
     */
    /**
     * 复制全部日志。
     *
     * 之前"点了没反应"三个原因：
     *      直接把已收集的内容清空 → 复制出空串
     *   2. 只读 logView，而 logView 属于服务面板，主界面时可能是初始占位文本
     *   3. 写导出目录在 Android 10+ 分区存储下会失败，且失败时没有任何兜底提示
     *
     * 现在的策略：
     *   - 内容 = 服务日志 + 操作日志 + logView，去重合并，不再互相清空
     *   - 复制同时写文件（MediaStore 优先，兼容 Android 10+）
     *   - 无论成功与否都弹日志查看框，用户可长按手动选中复制——
     *     这是最可靠的一条路，不依赖剪贴板 API 是否正常
     */
    void copyAll() {
        final String s = collectAllLog();
        if (s.isEmpty()) {
            toast("日志为空，无可复制");
            return;
        }
        File saved = saveLogToFile(s);
        boolean clipOk = false;
        try {
            android.content.ClipboardManager cm =
                    (android.content.ClipboardManager) getSystemService(CLIPBOARD_SERVICE);
            if (cm != null) {
                cm.setPrimaryClip(ClipData.newPlainText("R2B 日志", s));
                clipOk = true;
            }
        } catch (Exception e) {
            appendLog("剪贴板写入失败: " + e.getMessage());
        }
        String msg;
        if (clipOk && saved != null) {
            msg = "已复制 " + s.length() + " 字符\n已保存到 " + saved.getAbsolutePath();
        } else if (clipOk) {
            msg = "已复制 " + s.length() + " 字符（文件保存失败）";
        } else if (saved != null) {
            msg = "剪贴板不可用，已保存到 " + saved.getAbsolutePath();
        } else {
            msg = "复制与保存都失败，请用下面的查看框手动复制";
        }
        toast(msg);
        // 无论如何都把内容摊开给用户——长按即可选中复制，绕开剪贴板问题
        showLogViewDialog(s, msg);
    }

    /** 汇总所有日志来源，不再互相清空。 */
    String collectAllLog() {
        StringBuilder sb = new StringBuilder();
        try {
            String svcLog = McpForegroundService.bufferedLog();
            if (svcLog != null && svcLog.trim().length() > 0) {
                sb.append("===== 服务日志 =====\n").append(svLogTrim(svcLog)).append("\n");
            }
        } catch (Exception ignored) {}
        if (fullLog.length() > 0) {
            sb.append("\n===== 操作日志 =====\n").append(svLogTrim(fullLog.toString()));
        }
        if (logView != null && logView.getText() != null) {
            String v = logView.getText().toString().trim();
            // 只补 logView 里有、缓冲里没有的尾部内容，绝不清空已有内容
            if (v.length() > 0 && !sb.toString().contains(v.substring(0, Math.min(40, v.length())))) {
                sb.append("\n\n===== 面板日志 =====\n").append(v);
            }
        }
        return sb.toString().trim();
    }

    private static String svLogTrim(String x) {
        return x == null ? "" : x.trim();
    }

    /** 日志查看框：setTextIsSelectable，长按可全选复制。 */
    void showLogViewDialog(String content, String hint) {
        android.app.AlertDialog.Builder b = new android.app.AlertDialog.Builder(this);
        LinearLayout box = new LinearLayout(this);
        box.setOrientation(LinearLayout.VERTICAL);
        box.setPadding(dp(14), dp(10), dp(14), dp(6));

        if (hint != null && !hint.isEmpty()) {
            TextView h = tv(hint.replace("\n", " "), 12, 0xFF188038, true);
            box.addView(h);
        }
        TextView tip = tv("长按文本可全选复制", 11, 0xFF8A929E, false);
        box.addView(tip);

        final TextView body = new TextView(this);
        body.setText(content);
        body.setTextSize(11);
        body.setTypeface(Typeface.MONOSPACE);
        body.setTextColor(0xFF202124);
        body.setTextIsSelectable(true);
        body.setPadding(dp(6), dp(6), dp(6), dp(6));
        body.setBackground(roundRect(0xFFF5F7FA, dp(8)));

        android.widget.ScrollView sv = new android.widget.ScrollView(this);
        sv.addView(body);
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(-1, 0, 1f);
        box.addView(sv, lp);

        final String c = content;
        Button again = pill("再试一次复制", 0xFF1A73E8, 0xFFFFFFFF);
        again.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) {
                try {
                    android.content.ClipboardManager cm =
                            (android.content.ClipboardManager) getSystemService(CLIPBOARD_SERVICE);
                    if (cm != null) {
                        cm.setPrimaryClip(ClipData.newPlainText("R2B 日志", c));
                        toast("已复制 " + c.length() + " 字符");
                    }
                } catch (Exception e) {
                    toast("复制失败: " + e.getMessage());
                }
            }
        });
        box.addView(again, gap());

        b.setView(box);
        b.setNegativeButton("关闭", null);
        b.show();
    }

    /** 日志落盘到导出目录（用户能直接用文件管理器取到）。 */
    private File saveLogToFile(String s) {
        String name = "r2b_log_" + System.currentTimeMillis() + ".txt";
        // Android 10+ 分区存储：公共 Download 不能直接 File 写，走 MediaStore
        if (Build.VERSION.SDK_INT >= 29) {
            try {
                android.content.ContentValues cv = new android.content.ContentValues();
                cv.put(android.provider.MediaStore.MediaColumns.DISPLAY_NAME, name);
                cv.put(android.provider.MediaStore.MediaColumns.MIME_TYPE, "text/plain");
                cv.put(android.provider.MediaStore.MediaColumns.RELATIVE_PATH,
                        android.os.Environment.DIRECTORY_DOWNLOADS + "/Flutter分析结果");
                android.net.Uri uri = getContentResolver().insert(
                        android.provider.MediaStore.Downloads.EXTERNAL_CONTENT_URI, cv);
                if (uri != null) {
                    java.io.OutputStream os = getContentResolver().openOutputStream(uri);
                    if (os != null) {
                        os.write(s.getBytes("UTF-8"));
                        os.close();
                        appendLog("日志已保存到 Download/Flutter分析结果/" + name);
                        return new File(android.os.Environment
                                .getExternalStoragePublicDirectory(
                                        android.os.Environment.DIRECTORY_DOWNLOADS),
                                "Flutter分析结果/" + name);
                    }
                }
            } catch (Exception e) {
                appendLog("MediaStore 保存失败: " + e.getMessage());
            }
        }
        // 兜底：私有目录（一定能写）
        try {
            File dir = getExternalFilesDir(null);
            if (dir == null) dir = getFilesDir();
            File f = new File(dir, name);
            java.io.FileOutputStream os = new java.io.FileOutputStream(f);
            os.write(s.getBytes("UTF-8"));
            os.close();
            appendLog("日志已保存到 " + f.getAbsolutePath());
            return f;
        } catch (Exception e) {
            appendLog("保存失败: " + e.getMessage());
            return null;
        }
    }

    /** 剪贴板不可用时的兜底：写文件并提示路径。 */
    private void fallbackSaveLog(String s) {
        try {
            File dir = new File(getExternalFilesDir(null), "r2b_logs");
            if (!dir.exists()) dir.mkdirs();
            File f = new File(dir, "log_" + System.currentTimeMillis() + ".txt");
            java.io.FileOutputStream os = new java.io.FileOutputStream(f);
            os.write(s.getBytes("UTF-8"));
            os.close();
            toast("剪贴板不可用，已存到: " + f.getAbsolutePath());
            appendLog("日志已保存: " + f.getAbsolutePath());
        } catch (Exception e2) {
            toast("复制失败: " + e2.getMessage());
        }
    }

    void toast(final String msg) {
        ui.post(new Runnable() { public void run() {
            android.widget.Toast.makeText(MainActivity.this, msg,
                    android.widget.Toast.LENGTH_LONG).show();
        } });
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
    /**
     * 地址行。
     *
     * 之前"复制"按钮从创建到返回都没绑 OnClickListener——点了当然没反应。
     * 同时给地址文本开了 setTextIsSelectable：剪贴板 API 在部分 ROM 上
     * 静默失败，长按手动选中是唯一不依赖任何 API 的兜底路径。
     */
    LinearLayout svcRow(String label, final String url) {
        LinearLayout r = new LinearLayout(this);
        r.setGravity(Gravity.CENTER_VERTICAL);
        TextView l = tv(label, 14, 0xFF5F6368, false);
        LinearLayout.LayoutParams ll = new LinearLayout.LayoutParams(dp(60), -1);
        r.addView(l, ll);
        final TextView u = tv(url, 14, 0xFF202124, false);
        LinearLayout.LayoutParams ul = new LinearLayout.LayoutParams(0, -1, 1f);
        r.addView(u, ul);
        // 长按可选中复制，绕开剪贴板
        u.setTextIsSelectable(true);
        u.setFocusable(true);
        u.setFocusableInTouchMode(true);
        u.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) { doCopy(url, "地址"); }
        });
        Button c = pill("复制", 0xFFEEF1F5, 0xFF1A73E8);
        c.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) { doCopy(url, label + "地址"); }
        });
        r.addView(c);
        return r;
    }

    /**
     * 统一的复制入口。
     *
     * 剪贴板在部分 ROM 上会静默失败（setPrimaryClip 不抛异常但没写进去），
     * 所以这里写完立刻读回来校验，失败就告诉用户并建议长按选中——
     * 不再出现"点了没反应、也不知道成没成功"的情况。
     */
    void doCopy(String text, String what) {
        if (text == null || text.isEmpty()) { toast("没有可复制的内容"); return; }
        boolean ok = false;
        String err = null;
        try {
            android.content.ClipboardManager cm =
                    (android.content.ClipboardManager) getSystemService(CLIPBOARD_SERVICE);
            if (cm != null) {
                cm.setPrimaryClip(ClipData.newPlainText(what, text));
                // 读回来校验
                ok = cm.hasPrimaryClip()
                        && cm.getPrimaryClip() != null
                        && cm.getPrimaryClip().getItemCount() > 0
                        && text.equals(String.valueOf(
                                cm.getPrimaryClip().getItemAt(0).getText()));
            } else {
                err = "剪贴板服务为空";
            }
        } catch (Exception e) {
            err = e.getMessage();
        }
        if (ok) {
            toast("已复制 " + what);
        } else {
            toast("复制失败" + (err == null ? "" : "（" + err + "）")
                    + "，请长按文本手动选中复制");
        }
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
        // 102 = 选择导出目录
        if (req == 102 && res == RESULT_OK && data != null && data.getData() != null) {
            android.net.Uri tree = data.getData();
            try {
                // 授权持久化，重启后仍可写
                getContentResolver().takePersistableUriPermission(tree,
                        Intent.FLAG_GRANT_READ_URI_PERMISSION
                                | Intent.FLAG_GRANT_WRITE_URI_PERMISSION);
            } catch (Exception ignored) {}
            String p = resolveTreePath(tree);
            if (p != null) {
                android.preference.PreferenceManager.getDefaultSharedPreferences(this)
                        .edit().putString("export_dir", p).apply();
                toast("导出目录已设为: " + p);
                appendLog("导出目录: " + p);
                showSettings();   // 重新弹出以刷新显示
            } else {
                toast("已选择但无法解析为路径，请用文件管理器类应用再选一次");
            }
            return;
        }
        if (req != 101 || res != RESULT_OK || data == null || data.getData() == null) return;
        final android.net.Uri uri = data.getData();
        String shown = fileBox == null || fileBox.getText() == null
                ? "" : fileBox.getText().toString();
        final String real = resolvePickedPath(uri, shown);
        if (fileBox != null) {
            fileBox.setText(uri.getLastPathSegment());
            fileBox.setTextColor(0xFF1A73E8);
        }
        appendLog("已选择: " + uri);
        if (real == null) {
            appendLog("无法解析为本地路径，请尝试从内部存储选择");
            ApkResultCard.showResult(MainActivity.this, apkCard, "无法读取",
                    "拿不到本地路径：\n" + uri
                    + "\n\nAndroid 10+ 分区存储下，部分来源只能拿到 content:// URI。"
                    + "请改用文件管理器选择，或先把文件复制到内部存储。");
            return;
        }
        if (toolExec == null) toolExec = new ToolExecutor(this);
        toolExec.setCurrentApk(real);
        McpForegroundService.pushApkToService(real);

        // 立即在主界面解析并展示——不用切到服务页看日志
        final File f = new File(real);
        ApkResultCard.showResult(this, apkCard, "解析中…", f.getName());
        new Thread(new Runnable() { public void run() {
            final NativeAnalyzer.ApkInfo info = NativeAnalyzer.openApk(f);
            ui.post(new Runnable() { public void run() {
                ApkResultCard.render(MainActivity.this, apkCard, info, f,
                        new ApkResultCard.ActionListener() {
                            public void onAction(String action, String arg) {
                                runToolAction(action, arg);
                            }
                        });
                appendLog("解析完成: " + (info == null ? "失败" : info.entries.size() + " 个条目"));
            } });
            // 选完就自动往下跑，不用再手动点"分析 SO""提取字符串"
            autoAnalyzeAfterParse(info, f);
        } }).start();
    }

    /**
     * 解析完自动接着分析，不再要用户手动点。
     *
     * 顺序：
     *   1. 提取 DEX 字符串（任何 APK 都有，最快出结果）
     *   2. 有 native so 就解包主 so 并反汇编前几百字节
     *   3. 是 Flutter 且有 libapp.so 就额外跑 blutter
     * 每一步结果都追加到卡片，可以单独看。
     */
    /**
     * 选完 APK 后的自动分析流水线。
     *
     * 黑猫原版就是选完自动往下跑完，用户只等结果。这里分成阶段，
     * 每个阶段结果实时追加到卡片，不用等全部跑完才有反馈。
     *
     *   阶段 1  解包：DEX + 全部 native so → 导出目录
     *   阶段 2  DEX 字符串、类名、Manifest 关键项
     *   阶段 3  每个 so：ELF 头信息 + 符号表 + 字符串 + 反汇编前若干字节
     *   阶段 4  Flutter 有 libapp.so → blutter 符号
     *   阶段 5  汇总
     */
    /**
     * 选完 APK 后的自动分析流水线。
     *
     * 顺序（黑猫原版也是这个思路，只是它不告诉你每一步在干什么）：
     *   ① 壳检测 —— 有壳就先提示脱壳，不做无意义的解析
     *   ② 解包 —— DEX + 全部 native so
     *   ③ 按技术栈分流：
     *        Flutter  → blutter 解析 libapp.so
     *        Unity    → IL2CPP 符号还原
     *        原生      → DEX 字符串 / 类名 / Manifest
     *   ④ 每个 so 反汇编
     *   ⑤ 汇总
     */
    void autoAnalyzeAfterParse(final NativeAnalyzer.ApkInfo info, final File apk) {
        if (info == null) return;
        final long t0 = System.currentTimeMillis();

        new Thread(new Runnable() { public void run() {
            final StringBuilder sum = new StringBuilder();

            // ===== ① 壳检测 =====
            final NativeAnalyzer.PackerInfo pk = NativeAnalyzer.detectPacker(info);
            if (pk.packed) {
                appendCardSection("① 壳检测 ⚠ " + pk.name,
                        "证据: " + pk.evidence + "\n\n"
                        + "脱壳建议: " + pk.unpackHint + "\n\n"
                        + "加壳 APK 的 dex/so 是密文，下面的静态分析结果不可信，"
                        + "需先 dump 出解密后的 dex 再分析。");
                appendLog("检测到 " + pk.name + "：" + pk.evidence);
            } else {
                appendCardSection("① 壳检测 ✓ 无壳", "未发现已知加固特征，可直接静态分析。");
            }

            // ===== ② 解包 =====
            appendCardSection("② 解包中…", "→ " + exportDir().getAbsolutePath());
            int dexN = 0;
            if (info.dexes != null) {
                for (String dx : info.dexes) {
                    if (NativeAnalyzer.extractEntry(apk, dx, exportDir()) != null) dexN++;
                }
            }
            final java.util.List<String> soPaths = new java.util.ArrayList<String>();
            if (info.libs != null) {
                for (String lib : info.libs) {
                    File o = NativeAnalyzer.extractEntry(apk, lib, exportDir());
                    if (o != null) soPaths.add(o.getAbsolutePath());
                }
            }
            appendCardSection("② 解包完成",
                    "DEX " + dexN + " 个 · SO " + soPaths.size() + " 个\n"
                            + exportDir().getAbsolutePath());
            appendLog("解包完成: DEX " + dexN + ", SO " + soPaths.size());

            if (toolExec == null) toolExec = new ToolExecutor(MainActivity.this);

            // ===== ③ 按技术栈分流 =====
            if (info.hasFlutter) {
                // Flutter：blutter
                File appSo = null;
                for (String sp : soPaths) {
                    if (sp.endsWith("libapp.so")) { appSo = new File(sp); break; }
                }
                if (appSo == null) {
                    appendCardSection("③ Flutter 分析",
                            "检测到 Flutter（有 libflutter.so）但未找到 libapp.so。\n"
                            + "可能原因：\n"
                            + "  · so 被拆包 / 放在别的位置\n"
                            + "  · 是 debug 版或 split ABI 包\n"
                            + "  · 被加壳\n\n"
                            + "已列出的 so:\n" + joinLines(soPaths));
                } else {
                    try {
                        org.json.JSONObject a = new org.json.JSONObject();
                        a.put("so", appSo.getAbsolutePath());
                        a.put("path", appSo.getAbsolutePath());
                        a.put("apk_path", apk.getAbsolutePath());
                        appendCardSection("③ Flutter 符号 (blutter)",
                                toolExec.execute("Blutter_Analyze", a));
                    } catch (Throwable e) {
                        appendCardSection("③ Flutter 符号", "失败: " + e.getMessage());
                    }
                }
            } else if (info.hasIl2Cpp) {
                // Unity IL2CPP
                File cpp = null;
                for (String sp : soPaths) {
                    if (sp.endsWith("libil2cpp.so")) { cpp = new File(sp); break; }
                }
                if (cpp != null) {
                    try {
                        org.json.JSONObject a = new org.json.JSONObject();
                        a.put("so", cpp.getAbsolutePath());
                        a.put("path", cpp.getAbsolutePath());
                        appendCardSection("③ IL2CPP 符号",
                                toolExec.execute("Il2Cpp_Analyze", a));
                    } catch (Throwable e) {
                        appendCardSection("③ IL2CPP 符号", "失败: " + e.getMessage());
                    }
                }
            } else {
                // 原生：DEX 层
                try {
                    org.json.JSONObject a = new org.json.JSONObject();
                    a.put("apk_path", apk.getAbsolutePath());
                    a.put("path", apk.getAbsolutePath());
                    appendCardSection("③ DEX 字符串", toolExec.execute("Dex_Strings", a));
                } catch (Throwable e) {
                    appendCardSection("③ DEX 字符串", "失败: " + e.getMessage());
                }
            }

            // ===== ④ 每个 so 反汇编 =====
            for (int i = 0; i < soPaths.size(); i++) {
                final String so = soPaths.get(i);
                final int idx = i + 1;
                try {
                    org.json.JSONObject a = new org.json.JSONObject();
                    a.put("so", so); a.put("path", so); a.put("file", so);
                    a.put("offset", "0"); a.put("length", "2048");
                    a.put("arch", info.archs != null && info.archs.contains("arm64-v8a")
                            ? "arm64" : "arm");
                    appendCardSection("④ SO [" + idx + "/" + soPaths.size() + "] "
                            + new File(so).getName(),
                            toolExec.execute("Capstone_Disasm", a));
                } catch (Throwable e) {
                    appendCardSection("④ SO [" + idx + "]", "失败: " + e.getMessage());
                }
            }

            // ===== ⑤ 汇总 =====
            long ms = System.currentTimeMillis() - t0;
            sum.append("耗时 ").append(ms).append(" ms\n");
            sum.append("壳     ").append(pk.name).append('\n');
            sum.append("技术栈 ").append(info.hasFlutter ? "Flutter"
                    : (info.hasIl2Cpp ? "Unity/IL2CPP"
                    : (info.hasReactNative ? "React Native" : "原生 Java/Kotlin"))).append('\n');
            sum.append("DEX ").append(info.dexes == null ? 0 : info.dexes.size())
               .append(" · SO ").append(info.libs == null ? 0 : info.libs.size())
               .append(" · 条目 ").append(info.entries == null ? 0 : info.entries.size())
               .append('\n');
            sum.append("导出 ").append(exportDir().getAbsolutePath());
            appendCardSection("⑤ 汇总", sum.toString());
            appendLog("自动分析完成，耗时 " + ms + " ms");
        } }).start();
    }

    private static String joinLines(java.util.List<String> l) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < l.size() && i < 30; i++) {
            sb.append("  · ").append(new File(l.get(i)).getName()).append('\n');
        }
        if (l.size() > 30) sb.append("  … 还有 ").append(l.size() - 30).append(" 个");
        return sb.toString();
    }

    /** 选一个值得看的主 so：优先 Flutter/Unity 的，其次体积大的。 */
    String pickMainSo(NativeAnalyzer.ApkInfo info) {
        if (info.libs == null || info.libs.isEmpty()) return null;
        String[] pref = {"libapp.so", "libil2cpp.so", "libflutter.so",
                "libreactnativejni.so", "libunity.so"};
        for (String p : pref) {
            String e = findEntry(info, p);
            if (e != null) return e;
        }
        return info.libs.get(0);
    }

    String findEntry(NativeAnalyzer.ApkInfo info, String name) {
        if (info.libs == null) return null;
        for (String l : info.libs) {
            if (l.endsWith(name)) return l;
        }
        return null;
    }

    /** 后台线程里往卡片追加一段结果。 */
    void appendCardSection(final String title, final String body) {
        ui.post(new Runnable() { public void run() {
            ApkResultCard.appendSection(MainActivity.this, apkCard, title, body);
        } });
    }

    /** 把 ACTION_OPEN_DOCUMENT_TREE 的 tree uri 转成可读路径。 */
    String resolveTreePath(android.net.Uri tree) {
        if (tree == null) return null;
        String s = tree.toString();
        // content://com.android.externalstorage.documents/tree/primary:Download/xxx
        int i = s.indexOf("/tree/");
        if (i < 0) return null;
        String seg = s.substring(i + 6);
        try {
            seg = java.net.URLDecoder.decode(seg, "UTF-8");
        } catch (Exception ignored) {}
        if (seg.startsWith("primary:")) {
            return android.os.Environment.getExternalStorageDirectory()
                    + "/" + seg.substring(8);
        }
        // 其它存储（SD 卡）无法直接拼路径，退回 /storage/
        int colon = seg.indexOf(':');
        if (colon > 0) return "/storage/" + seg.substring(colon + 1);
        return seg;
    }

    /**
     * 卡片上的动作：真执行并把结果回显到卡片。
     *
     * 关键修正：APK 里的 so 是 zip 条目名（如 assets/hkp/core.so），
     * 不是磁盘路径。直接把它当路径传会给工具一个不存在的文件——
     * 这就是之前"没有文件路径"的由来。这里先解包到导出目录，
     * 再把真实绝对路径传给工具。
     */
    void runToolAction(final String action, final String arg) {
        appendLog("执行: " + action + " " + arg);
        ApkResultCard.showResult(this, apkCard, "执行中…", action
                + (arg == null || arg.isEmpty() ? "" : "\n" + arg));
        new Thread(new Runnable() { public void run() {
            String title = action;
            String body;
            try {
                if (toolExec == null) toolExec = new ToolExecutor(MainActivity.this);
                if ("strings".equals(action)) {
                    body = toolExec.execute("Dex_Strings", new org.json.JSONObject());
                } else {
                    // 先把条目解包成真实文件
                    String realPath = arg;
                    String apk = toolExec.getCurrentApk();
                    if (arg != null && !arg.isEmpty() && !new File(arg).isFile()
                            && apk != null) {
                        File out = NativeAnalyzer.extractEntry(
                                new File(apk), arg, exportDir());
                        if (out != null) {
                            realPath = out.getAbsolutePath();
                            appendLog("已解包: " + arg + " -> " + realPath);
                        } else {
                            appendLog("解包失败: " + arg);
                        }
                    }
                    if (realPath == null) {
                        body = "没有可分析的文件路径。\n"
                                + "当前 APK: " + (apk == null ? "(未选择)" : apk) + "\n"
                                + "条目: " + arg;
                    } else {
                        org.json.JSONObject a = new org.json.JSONObject();
                        a.put("so", realPath);
                        a.put("path", realPath);
                        a.put("file", realPath);
                        a.put("apk_path", apk);
                        a.put("offset", "0");
                        a.put("length", "4096");
                        body = "文件: " + realPath + "\n\n"
                                + toolExec.execute("Capstone_Disasm", a);
                    }
                }
            } catch (Throwable t) {
                body = "失败: " + t.getClass().getSimpleName() + ": " + t.getMessage();
            }
            final String tb = body, tt = title;
            ui.post(new Runnable() { public void run() {
                ApkResultCard.showResult(MainActivity.this, apkCard, tt + " 结果", tb);
            } });
        } }).start();
    }
}
