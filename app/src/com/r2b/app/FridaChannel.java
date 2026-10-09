package com.r2b.app;

import android.content.Context;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.util.ArrayList;
import java.util.List;

/**
 * Frida 双通道。
 *
 * 通道 A（gadget，无需 root）：
 *   内置 io_frida.so，生成 gadget 配置与 JS 脚本，由目标进程加载。
 *   这是黑猫的做法——它把 125MB 的 io_frida.so 打进 APK 就是为了这个。
 *
 * 通道 B（frida-server，需 root）：
 *   从 nativeLibraryDir 找到 frida-server 并拉起，监听 27042。
 *   启动后通道 A 的脚本同样可投递，但由服务端注入，能力更完整
 *   （可 spawn、可枚举设备/进程，gadget 只能改目标 APK）。
 *
 * 诚实边界：本类只负责「探测 + 拉起 + 端口健康 + 生成脚本」。
 * 与 frida-server 的实际 RPC（握手、脚本加载、消息回传）走的是 frida
 * 私有二进制协议，不在本类实现——需要时另开 FridaRpc。
 * 未就绪时 capabilities 如实返回 false，不伪装可用。
 */
public final class FridaChannel {

    private static final String TAG = "R2B_Frida";
    public static final int DEFAULT_PORT = 27042;

    public static class Status {
        public boolean serverRunning;      // 通道 B 就绪
        public boolean serverBinaryFound;  // frida-server 二进制存在
        public boolean gadgetAvailable;    // 通道 A 就绪
        public boolean rooted;
        public String serverPath;
        public String gadgetPath;
        public String mode;                // server | gadget | none
        public String detail;
        public String error;
    }

    private FridaChannel() {}

    /** 探测当前可用通道。 */
    public static Status probe(Context c) {
        Status s = new Status();
        s.rooted = hasRoot();

        // 通道 B：frida-server
        File srv = EngineUnpacker.findExecutable(c, "frida-server");
        if (srv == null) srv = EngineUnpacker.findExecutable(c, "frida-server-16.1.4-android-arm64");
        if (srv != null) {
            s.serverBinaryFound = true;
            s.serverPath = srv.getAbsolutePath();
        }
        s.serverRunning = portOpen(DEFAULT_PORT);

        // 通道 A：gadget
        File gadget = EngineUnpacker.findExecutable(c, "io_frida.so");
        if (gadget == null) gadget = EngineUnpacker.findExecutable(c, "libfrida-gadget.so");
        if (gadget != null) {
            s.gadgetAvailable = true;
            s.gadgetPath = gadget.getAbsolutePath();
        }

        if (s.serverRunning) {
            s.mode = "server";
            s.detail = "frida-server 已在 127.0.0.1:" + DEFAULT_PORT + " 监听";
        } else if (s.serverBinaryFound && s.rooted) {
            s.mode = "server";
            s.detail = "frida-server 存在但未运行，可调用 start() 拉起";
        } else if (s.gadgetAvailable) {
            s.mode = "gadget";
            s.detail = "无 root，走 gadget 注入（需把 io_frida.so 打进目标 APK）";
        } else {
            s.mode = "none";
            s.error = "frida-server 与 gadget 均不可用";
        }
        return s;
    }

    /** 拉起 frida-server（需 root）。 */
    public static String start(Context c) {
        File srv = EngineUnpacker.findExecutable(c, "frida-server");
        if (srv == null) {
            return "未找到 frida-server 可执行文件";
        }
        if (!hasRoot()) {
            return "未 root，无法启动 frida-server；请改用 gadget 通道";
        }
        if (portOpen(DEFAULT_PORT)) {
            return "frida-server 已在运行";
        }
        try {
            // 后台常驻：nohup 式拉起，父进程退出不牵连它
            List<String> cmd = new ArrayList<String>();
            String su = findSu();
            cmd.add(su != null ? su : "su");
            cmd.add("-c");
            cmd.add(srv.getAbsolutePath() + " -D");
            ProcessBuilder pb = new ProcessBuilder(cmd);
            pb.directory(srv.getParentFile());
            pb.redirectErrorStream(true);
            pb.environment().put("LD_LIBRARY_PATH", srv.getParent());
            pb.start();

            // 等待端口起来，最多 6 秒
            for (int i = 0; i < 30; i++) {
                Thread.sleep(200);
                if (portOpen(DEFAULT_PORT)) {
                    return "frida-server 已启动，监听 " + DEFAULT_PORT;
                }
            }
            return "已发起启动但未检测到端口（可能被 SELinux 拦截或需手动授权 root）";
        } catch (Exception e) {
            return "启动失败: " + e.getClass().getSimpleName() + ": " + e.getMessage();
        }
    }

    /** 生成 gadget 配置文件（通道 A 用）。 */
    public static File writeGadgetConfig(Context c, String scriptPath) {
        try {
            File dir = new File(c.getFilesDir(), "frida");
            if (!dir.exists()) dir.mkdirs();
            File cfg = new File(dir, "libfrida-gadget.config");
            String content;
            if (scriptPath != null && !scriptPath.isEmpty()) {
                content = "{\\n"
                        + "  \"interaction\": {\\n"
                        + "    \"type\": \"script\",\\n"
                        + "    \"path\": \\"" + scriptPath + "\\",\\n"
                        + "    \"on_load\": \"resume\"\\n"
                        + "  }\\n"
                        + "}\\n";
            } else {
                content = "{\\n"
                        + "  \"interaction\": {\\n"
                        + "    \"type\": \"listen\",\\n"
                        + "    \"address\": \"127.0.0.1\",\\n"
                        + "    \"port\": " + DEFAULT_PORT + ",\\n"
                        + "    \"on_load\": \"wait\"\\n"
                        + "  }\\n"
                        + "}\\n";
            }
            FileOutputStream os = new FileOutputStream(cfg);
            os.write(content.getBytes("UTF-8"));
            os.close();
            return cfg;
        } catch (IOException e) {
            return null;
        }
    }

    /** 生成一段可直接用的 hook 脚本（按 blutter 产出的符号）。 */
    public static String buildHookScript(String module, String addrHex, String logTag) {
        String m = module == null || module.isEmpty() ? "libapp.so" : module;
        String a = addrHex == null || addrHex.isEmpty() ? "0x0" : addrHex;
        String t = logTag == null || logTag.isEmpty() ? "hook" : logTag;
        return "// R2B 生成的 Frida hook 脚本\\n"
                + "const MOD = '" + m + "';\\n"
                + "const OFF = " + a + ";\\n"
                + "function attach() {\\n"
                + "  const base = Module.findBaseAddress(MOD);\\n"
                + "  if (!base) { setTimeout(attach, 300); return; }\\n"
                + "  const target = base.add(OFF);\\n"
                + "  Interceptor.attach(target, {\\n"
                + "    onEnter(args) {\\n"
                + "      console.log('[" + t + "] enter ' + target + "
                + "' args0=' + args[0] + ' args1=' + args[1]);\\n"
                + "    },\\n"
                + "    onLeave(retval) {\\n"
                + "      console.log('[" + t + "] leave ' + retval);\\n"
                + "    }\\n"
                + "  });\\n"
                + "  console.log('[" + t + "] hooked ' + MOD + ' + ' + OFF);\\n"
                + "}\\n"
                + "attach();\\n";
    }

    // ---------- 内部 ----------

    private static boolean portOpen(int port) {
        Socket s = null;
        try {
            s = new Socket();
            s.connect(new InetSocketAddress("127.0.0.1", port), 400);
            return true;
        } catch (Exception e) {
            return false;
        } finally {
            if (s != null) {
                try { s.close(); } catch (Exception ignored) {}
            }
        }
    }

    public static boolean hasRoot() {
        String su = findSu();
        if (su == null) return false;
        try {
            Process p = new ProcessBuilder(su, "-c", "id").start();
            java.io.InputStream is = p.getInputStream();
            byte[] b = new byte[256];
            int n = is.read(b);
            is.close();
            p.destroy();
            String out = n > 0 ? new String(b, 0, n, "UTF-8") : "";
            return out.contains("uid=0");
        } catch (Exception e) {
            return false;
        }
    }

    private static String findSu() {
        String[] paths = {"/system/bin/su", "/system/xbin/su", "/sbin/su",
                "/system/sbin/su", "/vendor/bin/su"};
        for (String p : paths) {
            if (new File(p).exists()) return p;
        }
        return null;
    }
}
