package com.r2b.app;

import android.app.Service;
import android.content.Intent;
import android.os.Bundle;
import android.os.Handler;
import android.os.HandlerThread;
import android.os.IBinder;
import android.os.Message;
import android.os.Messenger;
import android.os.RemoteException;
import android.util.Log;

/**
 * radare2 执行服务，跑在独立进程 :r2。
 *
 * 为什么必须独立进程——这是崩溃问题的根治，不是绕开：
 *
 * radare2 通过 JNI 桥 dlopen 进进程，一旦它在 native 里 SIGSEGV，
 * 死的是整个进程，Java 的 try/catch 完全拦不住。
 * 之前它跑在 MCP 服务进程里，于是一次崩溃 = 5051 整个挂掉 =
 * 客户端看到 "Server disconnected"，且必须重启 App 才能恢复。
 * 测试里 26 次断连就是这么来的。
 *
 * 挪到独立进程后：崩溃只杀 :r2 这一个进程，MCP 服务进程不受影响。
 * 主进程通过 binder 死亡通知感知到崩溃，下次调用自动重新拉起 :r2。
 * 对客户端来说，最坏情况是"这个工具失败了"，而不是"整个服务没了"。
 *
 * 这个进程里唯一要做的事就是执行 r2 命令，不做任何别的。
 */
public class R2RemoteService extends Service {

    private static final String TAG = "R2B_R2Remote";

    /** 主进程 -> :r2：执行一条命令。data 里放 "cmd" 或 "op"+"path"。 */
    public static final int MSG_EXEC = 1;
    /** 主进程 -> :r2：打开一个文件。 */
    public static final int MSG_OPEN = 2;
    /** 主进程 -> :r2：自检。 */
    public static final int MSG_TEST = 3;
    /** 主进程 -> :r2：Capstone 反汇编（capstone 同样会 native 崩溃，一起隔离）。 */
    public static final int MSG_DISASM = 4;
    /** :r2 -> 主进程：结果。 */
    public static final int MSG_RESULT = 100;

    public static final String K_CMD = "cmd";
    public static final String K_PATH = "path";
    public static final String K_OUT = "out";
    public static final String K_OK = "ok";

    private Messenger serverMessenger;
    private HandlerThread worker;
    private Handler handler;

    @Override
    public void onCreate() {
        super.onCreate();
        worker = new HandlerThread("r2-exec", android.os.Process.THREAD_PRIORITY_DEFAULT);
        worker.start();
        handler = new Handler(worker.getLooper()) {
            @Override
            public void handleMessage(Message msg) {
                Bundle data = msg.getData();
                String out;
                boolean ok;
                switch (msg.what) {
                    case MSG_OPEN: {
                        String p = data == null ? null : data.getString(K_PATH);
                        out = Radare2Bridge.open(p);
                        ok = out != null && !out.toLowerCase().contains("失败")
                                && !out.toLowerCase().contains("error")
                                && !out.toLowerCase().contains("拒绝");
                        break;
                    }
                    case MSG_TEST: {
                        out = Radare2Bridge.test();
                        ok = out != null && out.contains("OK");
                        break;
                    }
                    case MSG_DISASM: {
                        // 参数走 JSON：{"hex":"...","addr":...,"arch":...,"mode":...,"count":...}
                        out = doDisasm(data == null ? null : data.getString(K_CMD));
                        ok = out != null && !out.startsWith("{")
                                ? !out.contains("\"error\"") : true;
                        ok = out != null && !out.contains("\"error\"");
                        break;
                    }
                    case MSG_EXEC:
                    default: {
                        String c = data == null ? null : data.getString(K_CMD);
                        out = Radare2Bridge.cmd(c);
                        ok = out != null && !out.startsWith("radare2 未")
                                && !out.startsWith("命令为空");
                        break;
                    }
                }
                // 回复。replyTo 为空说明调用方不需要结果，直接丢弃。
                if (msg.replyTo == null) return;
                Message reply = Message.obtain();
                reply.what = MSG_RESULT;
                Bundle rb = new Bundle();
                rb.putString(K_OUT, out == null ? "" : out);
                rb.putBoolean(K_OK, ok);
                reply.setData(rb);
                try {
                    msg.replyTo.send(reply);
                } catch (RemoteException e) {
                    Log.w(TAG, "回传结果失败: " + e.getMessage());
                }
            }
        };
        serverMessenger = new Messenger(handler);

        // 加载放在 :r2 进程里做：加载本身也可能崩，同样不能带累主进程
        try {
            Radare2Bridge.load(this);
        } catch (Throwable t) {
            Log.e(TAG, "radare2 加载异常: " + t.getMessage());
        }
    }

    /** 在 :r2 进程里跑 capstone，返回一个 JSON 字符串。 */
    private static String doDisasm(String jsonArgs) {
        try {
            org.json.JSONObject o = new org.json.JSONObject(
                    jsonArgs == null ? "{}" : jsonArgs);
            String hex = o.optString("hex", null);
            if (hex == null || hex.isEmpty()) {
                return "{\"error\":\"缺少 hex\"}";
            }
            byte[] code = new byte[hex.length() / 2];
            for (int i = 0; i < code.length; i++) {
                code[i] = (byte) Integer.parseInt(hex.substring(i * 2, i * 2 + 2), 16);
            }
            long addr = o.optLong("addr", 0);
            int arch = o.optInt("arch", CapstoneJni.ARCH_ARM64);
            int mode = o.optInt("mode", CapstoneJni.MODE_LITTLE_ENDIAN);
            int count = o.optInt("count", 0);
            java.util.List<CapstoneJni.Insn> insns =
                    CapstoneJni.disasm(code, addr, arch, mode, count);
            if (insns == null) {
                return "{\"error\":\"capstone 不可用: " + CapstoneJni.lastError() + "\"}";
            }
            org.json.JSONArray arr = new org.json.JSONArray();
            for (CapstoneJni.Insn n : insns) {
                org.json.JSONObject j = new org.json.JSONObject();
                j.put("address", n.address);
                j.put("mnemonic", n.mnemonic);
                j.put("op_str", n.opStr);
                j.put("bytes", n.bytes);
                arr.put(j);
            }
            org.json.JSONObject r = new org.json.JSONObject();
            r.put("engine", "capstone");
            r.put("count", arr.length());
            r.put("insns", arr);
            return r.toString();
        } catch (Throwable t) {
            return "{\"error\":\"" + t.getClass().getSimpleName() + ": "
                    + String.valueOf(t.getMessage()).replace("\"", "'") + "\"}";
        }
    }

    @Override
    public IBinder onBind(Intent intent) {
        return serverMessenger.getBinder();
    }

    @Override
    public void onDestroy() {
        if (worker != null) worker.quitSafely();
        super.onDestroy();
    }
}
