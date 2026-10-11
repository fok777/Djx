package com.r2b.app;

import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.ServiceConnection;
import android.os.Bundle;
import android.os.Handler;
import android.os.IBinder;
import android.os.Looper;
import android.os.Message;
import android.os.Messenger;
import android.os.RemoteException;
import android.util.Log;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

/**
 * 主进程侧的 :r2 远程执行客户端。
 *
 * 存在意义只有一个：radare2 / capstone 的 native 崩溃会杀掉整个进程，
 * Java 的 try/catch 拦不住。把它们挪到 :r2 进程后，崩溃只影响那一个进程，
 * MCP 服务（5051）继续存活。
 *
 * 对外表现：调用方永远拿到一个 Result（成功或错误），
 * 不会因为对端崩溃而把整个服务带走。
 */
public final class R2Remote {

    private static final String TAG = "R2B_R2Remote";

    /** 单次执行超时。r2 的 aaa 全量分析可能很慢，给足。 */
    private static final long TIMEOUT_MS = 120_000;

    private static volatile R2Remote inst;

    private final Context appCtx;
    private final Handler main = new Handler(Looper.getMainLooper());
    private final Object lock = new Object();

    private Messenger server;
    private boolean bound;
    /** 上次是否探测到对端崩溃（用于给调用方更准确的说明）。 */
    private volatile boolean lastCrashed;

    private R2Remote(Context c) {
        this.appCtx = c.getApplicationContext();
    }

    public static R2Remote get(Context c) {
        if (inst == null) {
            synchronized (R2Remote.class) {
                if (inst == null) inst = new R2Remote(c);
            }
        }
        return inst;
    }

    private final ServiceConnection conn = new ServiceConnection() {
        @Override
        public void onServiceConnected(ComponentName name, IBinder service) {
            synchronized (lock) {
                server = new Messenger(service);
                bound = true;
                lock.notifyAll();
            }
        }

        @Override
        public void onServiceDisconnected(ComponentName name) {
            // 注意：这个回调只在进程被杀时触发（正常 unbind 不会）
            synchronized (lock) {
                server = null;
                bound = false;
                lastCrashed = true;
                lock.notifyAll();
            }
            Log.w(TAG, ":r2 进程已断开（很可能崩溃）");
        }

        @Override
        public void onBindingDied(ComponentName name) {
            synchronized (lock) {
                server = null;
                bound = false;
                lastCrashed = true;
                lock.notifyAll();
            }
            Log.w(TAG, ":r2 绑定死亡（进程崩溃）");
        }
    };

    public static final class Result {
        public final boolean ok;
        public final String out;
        /** 对端进程是否崩溃（区别于"命令执行失败"）。 */
        public final boolean crashed;

        Result(boolean ok, String out, boolean crashed) {
            this.ok = ok;
            this.out = out;
            this.crashed = crashed;
        }
    }

    /** 绑定 :r2。返回 false 表示绑定失败。 */
    private boolean ensureBound() {
        synchronized (lock) {
            if (bound && server != null) return true;
        }
        final CountDownLatch latch = new CountDownLatch(1);
        final AtomicReference<Boolean> okRef = new AtomicReference<Boolean>(false);
        // bindService 的回调跑在主线程，所以这里 post 到主线程执行
        main.post(new Runnable() {
            @Override
            public void run() {
                try {
                    Intent i = new Intent(appCtx, R2RemoteService.class);
                    boolean b = appCtx.bindService(i, conn,
                            Context.BIND_AUTO_CREATE | Context.BIND_IMPORTANT);
                    okRef.set(b);
                } catch (Throwable t) {
                    Log.e(TAG, "bindService 异常: " + t.getMessage());
                    okRef.set(false);
                }
                latch.countDown();
            }
        });
        try {
            latch.await(10, TimeUnit.SECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return false;
        }
        if (!Boolean.TRUE.equals(okRef.get())) return false;
        // 等 onServiceConnected
        synchronized (lock) {
            long deadline = System.currentTimeMillis() + 15000;
            while (!bound && System.currentTimeMillis() < deadline) {
                try {
                    lock.wait(500);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    break;
                }
            }
            return bound && server != null;
        }
    }

    /** 执行一次远程调用。what 为 MSG_EXEC / MSG_OPEN / MSG_TEST / MSG_DISASM。 */
    private Result call(int what, String key, String value) {
        if (!ensureBound()) {
            return new Result(false,
                    "无法启动 radare2 隔离进程（:r2）。"
                    + "可能原因：Manifest 未声明该服务，或系统拒绝创建新进程。", false);
        }
        Messenger svr;
        synchronized (lock) {
            svr = server;
        }
        if (svr == null) return new Result(false, ":r2 未就绪", lastCrashed);

        final CountDownLatch latch = new CountDownLatch(1);
        final AtomicReference<String> outRef = new AtomicReference<String>();
        final AtomicReference<Boolean> okRef = new AtomicReference<Boolean>(false);

        Messenger reply = new Messenger(new Handler(Looper.getMainLooper()) {
            @Override
            public void handleMessage(Message msg) {
                if (msg.what == R2RemoteService.MSG_RESULT) {
                    Bundle d = msg.getData();
                    outRef.set(d == null ? "" : d.getString(R2RemoteService.K_OUT, ""));
                    okRef.set(d != null && d.getBoolean(R2RemoteService.K_OK, false));
                }
                latch.countDown();
            }
        });

        try {
            Message m = Message.obtain();
            m.what = what;
            Bundle b = new Bundle();
            b.putString(key, value);
            m.setData(b);
            m.replyTo = reply;
            svr.send(m);
        } catch (RemoteException e) {
            lastCrashed = true;
            return new Result(false, ":r2 进程通信失败（可能已崩溃）: " + e.getMessage(), true);
        }

        boolean done;
        try {
            done = latch.await(TIMEOUT_MS, TimeUnit.MILLISECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return new Result(false, "调用被中断", false);
        }
        if (!done) {
            // 超时几乎必然意味着 native 里卡死或进程已崩
            lastCrashed = true;
            return new Result(false,
                    "radare2 执行超时（" + TIMEOUT_MS / 1000 + "s）。"
                    + "通常是 :r2 进程在 native 里崩溃或死循环；"
                    + "该崩溃已被隔离，MCP 服务仍然存活。", true);
        }
        return new Result(Boolean.TRUE.equals(okRef.get()),
                outRef.get() == null ? "" : outRef.get(), lastCrashed);
    }

    // ---------- 对外接口 ----------

    /** 执行一条 r2 命令。 */
    public Result cmd(String command) {
        return call(R2RemoteService.MSG_EXEC, R2RemoteService.K_CMD, command);
    }

    /** 打开一个文件。 */
    public Result open(String path) {
        return call(R2RemoteService.MSG_OPEN, R2RemoteService.K_PATH, path);
    }

    /** 自检（与工具执行走同一进程、同一桥，结果才可信）。 */
    public Result test() {
        return call(R2RemoteService.MSG_TEST, R2RemoteService.K_CMD, "");
    }

    /** Capstone 反汇编（同样隔离，它也会 native 崩溃）。 */
    public Result disasm(String jsonArgs) {
        return call(R2RemoteService.MSG_DISASM, R2RemoteService.K_CMD, jsonArgs);
    }

    public boolean lastCrashed() { return lastCrashed; }
}
