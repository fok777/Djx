package com.r2b.app;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.os.Build;
import android.util.Log;

/**
 * 开机 / 包更新后自动拉起 MCP 服务。
 *
 * 参照「Flutter 解析工具 8.0」逆向得出：它注册了
 *   BOOT_COMPLETED / LOCKED_BOOT_COMPLETED / MY_PACKAGE_REPLACED / QUICKBOOT_POWERON
 * 四个广播，配合前台服务实现开机自启——这是它比旧版不容易挂的原因之一。
 *
 * 注意两点：
 *   1. Android 10+ 后台启动服务受限，但前台服务在 BOOT_COMPLETED 中
 *      是允许的例外场景之一（需用 startForegroundService）。
 *   2. LOCKED_BOOT_COMPLETED 用于开機後尚未解锁（Direct Boot）阶段，
 *      此时不能访问加密存储，所以这里只启动服务、不释放引擎资产
 *      （引擎释放推迟到用户解锁后由 EngineUnpacker 处理）。
 */
public class BootReceiver extends BroadcastReceiver {

    private static final String TAG = "R2B_Boot";

    @Override
    public void onReceive(Context context, Intent intent) {
        String action = intent == null ? "" : intent.getAction();
        if (action == null) return;

        boolean shouldStart =
                Intent.ACTION_BOOT_COMPLETED.equals(action)
                || Intent.ACTION_MY_PACKAGE_REPLACED.equals(action)
                // Direct Boot 阶段的开机完成
                || "android.intent.action.LOCKED_BOOT_COMPLETED".equals(action)
                // 部分 ROM（如 MTK / 展讯）的私有开机广播
                || "android.intent.action.QUICKBOOT_POWERON".equals(action);

        if (!shouldStart) return;

        // 只有在用户之前开过服务时才自动恢复，避免装上就常驻
        boolean wasRunning = android.preference.PreferenceManager
                .getDefaultSharedPreferences(context)
                .getBoolean("auto_start_service", false);
        if (!wasRunning) {
            Log.i(TAG, "服务此前未运行，跳过自启（" + action + "）");
            return;
        }

        try {
            Intent svc = new Intent(context, McpForegroundService.class);
            svc.setAction(McpForegroundService.ACTION_START);
            svc.putExtra(McpForegroundService.EXTRA_PORT, 5051);
            String backend = android.preference.PreferenceManager
                    .getDefaultSharedPreferences(context).getString("backend_url", "");
            svc.putExtra(McpForegroundService.EXTRA_BACKEND, backend);
            if (Build.VERSION.SDK_INT >= 26) {
                context.startForegroundService(svc);
            } else {
                context.startService(svc);
            }
            Log.i(TAG, "已自启 MCP 服务（" + action + "）");
        } catch (Exception e) {
            Log.e(TAG, "自启失败", e);
        }
    }
}
