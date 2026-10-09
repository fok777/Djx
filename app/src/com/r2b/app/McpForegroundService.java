package com.r2b.app;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.Service;
import android.content.Context;
import android.content.Intent;
import android.net.wifi.WifiManager;
import android.os.Build;
import android.os.IBinder;
import android.os.PowerManager;
import android.util.Log;

import java.util.ArrayList;
import java.util.List;

/**
 * MCP 前台服务。
 *
 * 这是稳定性的核心。旧架构把 ServerSocket 开在 Activity 的线程里，
 * Activity 一旦被系统回收（切后台、内存紧张、熄屏），线程立刻被杀，
 * 表现就是"挂着挂着就闪退 / 服务没了"。
 *
 * 放进前台 Service 后：
 *   - 进程优先级提升到前台，系统不会轻易回收
 *   - 通知栏常驻，用户可感知服务在运行
 *   - START_STICKY：进程被杀后系统会尝试重建
 *   - WakeLock + WifiLock：熄屏后 CPU 与 WiFi 不休眠，socket 不断连
 *
 * Activity 只做控制面板，通过 startService / stopService 控制本服务，
 * 自身销毁不影响服务运行。
 */
public class McpForegroundService extends Service {

    private static final String TAG = "R2B_Svc";
    private static final int NOTIFY_ID = 5051;
    private static final String CHANNEL_ID = "r2b_mcp";

    public static final String ACTION_START = "com.r2b.app.START_MCP";
    public static final String ACTION_STOP = "com.r2b.app.STOP_MCP";
    public static final String EXTRA_BACKEND = "backend_url";
    public static final String EXTRA_PORT = "port";

    /** 日志回调：Activity 可注册以接收服务侧日志。 */
    public interface LogSink {
        void onLog(String line);
    }

    private static final List<LogSink> SINKS = new ArrayList<LogSink>();
    private static final List<String> LOGBUF = new ArrayList<String>();
    private static final int LOGBUF_MAX = 400;

    public static void addSink(LogSink s) {
        synchronized (SINKS) {
            if (!SINKS.contains(s)) SINKS.add(s);
        }
    }

    public static void removeSink(LogSink s) {
        synchronized (SINKS) {
            SINKS.remove(s);
        }
    }

    /** 取历史日志（供 Activity 重建后恢复显示）。 */
    public static String bufferedLog() {
        synchronized (LOGBUF) {
            StringBuilder sb = new StringBuilder();
            for (String s : LOGBUF) sb.append(s).append('\n');
            return sb.toString();
        }
    }

    private static void emit(String line) {
        synchronized (LOGBUF) {
            LOGBUF.add(line);
            while (LOGBUF.size() > LOGBUF_MAX) LOGBUF.remove(0);
        }
        final String f = line;
        synchronized (SINKS) {
            for (LogSink s : SINKS) {
                try {
                    s.onLog(f);
                } catch (Exception ignored) {
                }
            }
        }
    }

    private McpService mcp;
    private PowerManager.WakeLock wakeLock;
    private WifiManager.WifiLock wifiLock;

    @Override
    public void onCreate() {
        super.onCreate();
        createChannel();
        acquireLocks();
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        if (intent != null && ACTION_STOP.equals(intent.getAction())) {
            stopSelf();
            return START_NOT_STICKY;
        }

        int port = intent != null ? intent.getIntExtra(EXTRA_PORT, 5051) : 5051;
        String backend = intent != null ? intent.getStringExtra(EXTRA_BACKEND) : "";

        // 必须在 startService 后 5 秒内调用 startForeground，否则 ANR / 崩溃
        startForeground(NOTIFY_ID, buildNotification("服务启动中…"));

        if (mcp != null && mcp.isRunning()) {
            emit("服务已在运行，端口 " + port);
            updateNotify("服务运行中 · 端口 " + port);
            return START_STICKY;
        }

        String toolsJson = "{}";
        try {
            java.io.InputStream is = getAssets().open("tools_data.json");
            java.io.ByteArrayOutputStream bo = new java.io.ByteArrayOutputStream();
            byte[] buf = new byte[8192];
            int n;
            while ((n = is.read(buf)) > 0) bo.write(buf, 0, n);
            is.close();
            toolsJson = new String(bo.toByteArray(), "UTF-8");
        } catch (Exception e) {
            Log.w(TAG, "读取 tools_data.json 失败", e);
        }

        mcp = new McpService(port, backend == null ? "" : backend, toolsJson,
                new McpService.Sink() {
                    public void onLog(String line) {
                        emit(line);
                    }
                });
        mcp.start();

        // 起服务顺带确保引擎已释放（幂等，已释放则跳过）
        new Thread(new Runnable() {
            public void run() {
                try {
                    EngineUnpacker u = new EngineUnpacker(McpForegroundService.this, null);
                    if (!u.isUnpacked()) {
                        emit("开始释放引擎资产…");
                        int n = u.unpack();
                        emit("引擎释放完成：" + n + " 个文件");
                    } else {
                        emit("引擎已就绪");
                    }
                    emit(EngineUnpacker.describe(McpForegroundService.this));
                } catch (Exception e) {
                    emit("引擎释放失败: " + e.getMessage());
                }
            }
        }).start();

        emit("MCP 服务已在前台服务中启动，端口 " + port);
        updateNotify("服务运行中 · 端口 " + port);
        return START_STICKY;
    }

    private void acquireLocks() {
        try {
            PowerManager pm = (PowerManager) getSystemService(Context.POWER_SERVICE);
            if (pm != null) {
                wakeLock = pm.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "R2B:McpWake");
                wakeLock.setReferenceCounted(false);
                wakeLock.acquire();
            }
        } catch (Exception e) {
            Log.w(TAG, "WakeLock 获取失败", e);
        }
        try {
            WifiManager wm = (WifiManager) getApplicationContext()
                    .getSystemService(Context.WIFI_SERVICE);
            if (wm != null) {
                wifiLock = wm.createWifiLock(WifiManager.WIFI_MODE_FULL_HIGH_PERF, "R2B:McpWifi");
                wifiLock.setReferenceCounted(false);
                wifiLock.acquire();
            }
        } catch (Exception e) {
            Log.w(TAG, "WifiLock 获取失败", e);
        }
    }

    private void releaseLocks() {
        try {
            if (wakeLock != null && wakeLock.isHeld()) wakeLock.release();
        } catch (Exception ignored) {
        }
        try {
            if (wifiLock != null && wifiLock.isHeld()) wifiLock.release();
        } catch (Exception ignored) {
        }
    }

    private void createChannel() {
        if (Build.VERSION.SDK_INT < 26) return;
        NotificationManager nm = getSystemService(NotificationManager.class);
        if (nm == null) return;
        if (nm.getNotificationChannel(CHANNEL_ID) != null) return;
        NotificationChannel ch = new NotificationChannel(
                CHANNEL_ID, "R2B MCP 服务", NotificationManager.IMPORTANCE_LOW);
        ch.setDescription("MCP 服务运行时常驻，停止服务后消失");
        ch.setShowBadge(false);
        nm.createNotificationChannel(ch);
    }

    private Notification buildNotification(String text) {
        Notification.Builder nb;
        if (Build.VERSION.SDK_INT >= 26) {
            nb = new Notification.Builder(this, CHANNEL_ID);
        } else {
            nb = new Notification.Builder(this);
        }
        nb.setContentTitle("R2B MCP 服务")
          .setContentText(text)
          .setSmallIcon(android.R.drawable.stat_sys_download)
          .setOngoing(true)
          .setWhen(System.currentTimeMillis());
        if (Build.VERSION.SDK_INT >= 21) nb.setCategory(Notification.CATEGORY_SERVICE);
        return nb.build();
    }

    private void updateNotify(String text) {
        NotificationManager nm = (NotificationManager) getSystemService(NOTIFICATION_SERVICE);
        if (nm != null) nm.notify(NOTIFY_ID, buildNotification(text));
    }

    @Override
    public void onDestroy() {
        emit("MCP 服务停止");
        if (mcp != null) {
            mcp.stop();
            mcp = null;
        }
        releaseLocks();
        if (Build.VERSION.SDK_INT >= 24) stopForeground(STOP_FOREGROUND_REMOVE);
        super.onDestroy();
    }

    /** 用户从最近任务划掉时触发：不自杀，保持服务存活。 */
    @Override
    public void onTaskRemoved(Intent rootIntent) {
        super.onTaskRemoved(rootIntent);
        Log.i(TAG, "任务被移除，服务保持运行");
    }

    @Override
    public IBinder onBind(Intent intent) {
        return null;
    }
}
