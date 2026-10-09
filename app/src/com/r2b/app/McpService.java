package com.r2b.app;

import android.content.Context;
import android.util.Log;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.Charset;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * 应用内 MCP 服务（Streamable HTTP 传输）。
 *
 * 让本机直接当 MCP 服务端用：客户端连 http://IP:5051/mcp 即可拿到完整工具表，
 * 无需额外跑 Python 后端。
 *
 * 方法：
 *   initialize    协议版本 + serverInfo
 *   tools/list    全部工具定义（含 inputSchema）
 *   tools/call    转发到 Python 后端；未配置则返回明确错误
 */
public class McpService {
    /** 日志缓冲：低价值消息进这里，不刷 UI。 */
    private final StringBuilder logBuf = new StringBuilder();
    String drainLog() { String r = logBuf.toString(); logBuf.setLength(0); return r; }
    private static final String TAG = "R2B_MCP";
    private static final String PROTOCOL = "2025-06-18";

    public interface Sink {
        void onLog(String line);
    }

    private final Context ctx;
    private final int port;
    private final String backendUrl;   // 为空表示本机执行
    private final String toolsJson;    // assets/tools_data.json 原文
    private final Sink sink;
    private final ToolExecutor executor;

    private ServerSocket server;
    private ExecutorService pool;
    private volatile boolean running;

    public McpService(Context ctx, int port, String backendUrl, String toolsJson, Sink sink) {
        this.ctx = ctx.getApplicationContext();
        this.port = port;
        this.backendUrl = backendUrl;
        this.toolsJson = toolsJson;
        this.sink = sink;
        this.executor = new ToolExecutor(ctx);
    }

    public ToolExecutor executor() { return executor; }

    public boolean isRunning() {
        return running;
    }

    public void start() {
        if (running) return;
        pool = Executors.newCachedThreadPool();
        pool.execute(new Runnable() {
            public void run() {
                try {
                    server = new ServerSocket();
                    server.setReuseAddress(true);
                    server.bind(new InetSocketAddress("0.0.0.0", port));
                    running = true;
                    log("MCP 服务启动在 0.0.0.0:" + port);
                    log("工具数 " + toolCount() + " · 协议 " + PROTOCOL);
                    while (running) {
                        Socket s;
                        try {
                            s = server.accept();
                        } catch (Exception e) {
                            if (running) log("accept 失败: " + e.getMessage());
                            break;
                        }
                        final Socket sock = s;
                        pool.execute(new Runnable() {
                            public void run() {
                                handle(sock);
                            }
                        });
                    }
                } catch (Exception e) {
                    log("启动失败: " + e.getMessage());
                    running = false;
                }
            }
        });
    }

    public void stop() {
        running = false;
        try {
            if (server != null) server.close();
        } catch (Exception ignored) {
        }
        if (pool != null) pool.shutdownNow();
        log("服务已停止");
    }

    private void log(String s) {
        if (sink != null) sink.onLog(s);
        Log.i(TAG, s);
    }

    private int toolCount() {
        try {
            JSONObject o = new JSONObject(toolsJson);
            return o.optInt("tool_total", 0);
        } catch (Exception e) {
            return 0;
        }
    }

    /** tools/list 的返回体：把 assets 里的分类数据摊平成工具数组。 */
    private JSONArray buildToolList() {
        JSONArray out = new JSONArray();
        try {
            JSONObject root = new JSONObject(toolsJson);
            JSONArray engines = root.optJSONArray("engines");
            if (engines == null) return out;
            for (int i = 0; i < engines.length(); i++) {
                JSONObject e = engines.optJSONObject(i);
                if (e == null) continue;
                JSONArray ts = e.optJSONArray("tools");
                if (ts == null) continue;
                for (int j = 0; j < ts.length(); j++) {
                    JSONObject t = ts.optJSONObject(j);
                    if (t == null) continue;
                    JSONObject item = new JSONObject();
                    item.put("name", t.optString("name"));
                    item.put("description", t.optString("desc"));
                    JSONObject schema = new JSONObject();
                    schema.put("type", "object");
                    schema.put("properties", new JSONObject());
                    schema.put("required", new JSONArray());
                    item.put("inputSchema", schema);
                    out.put(item);
                }
            }
        } catch (Exception e) {
            log("构建工具表失败: " + e.getMessage());
        }
        return out;
    }

    private String rpcResult(Object id, Object result) {
        JSONObject r = new JSONObject();
        try {
            r.put("jsonrpc", "2.0");
            r.put("id", id);
            r.put("result", result);
        } catch (Exception e) {
            return "{}";
        }
        return r.toString();
    }

    private String rpcError(Object id, int code, String msg) {
        JSONObject r = new JSONObject();
        try {
            r.put("jsonrpc", "2.0");
            r.put("id", id);
            JSONObject err = new JSONObject();
            err.put("code", code);
            err.put("message", msg);
            r.put("error", err);
        } catch (Exception e) {
            return "{}";
        }
        return r.toString();
    }

    /** 转发 tools/call 到 Python 后端（如果配了）。 */
    private String forward(String raw) {
        if (backendUrl == null || backendUrl.length() == 0) {
            return null;
        }
        java.net.HttpURLConnection c = null;
        try {
            java.net.URL u = new java.net.URL(backendUrl);
            c = (java.net.HttpURLConnection) u.openConnection();
            c.setRequestMethod("POST");
            c.setRequestProperty("Content-Type", "application/json");
            c.setConnectTimeout(3000);
            c.setReadTimeout(30000);
            c.setDoOutput(true);
            OutputStream os = c.getOutputStream();
            os.write(raw.getBytes("UTF-8"));
            os.flush();
            os.close();
            InputStream is = c.getInputStream();
            String body = readAll(is);
            is.close();
            return body;
        } catch (Exception e) {
            log("转发失败: " + e.getMessage());
            return null;
        } finally {
            if (c != null) c.disconnect();
        }
    }

    private static String readAll(InputStream is) throws Exception {
        ByteArrayOutputStream bo = new ByteArrayOutputStream();
        byte[] buf = new byte[8192];
        int n;
        while ((n = is.read(buf)) > 0) bo.write(buf, 0, n);
        return new String(bo.toByteArray(), Charset.forName("UTF-8"));
    }

    /** 处理单条 JSON-RPC 请求。 */
    String dispatch(String raw) {
        Object id = null;
        try {
            JSONObject req = new JSONObject(raw);
            id = req.opt("id");
            String method = req.optString("method", "");
            if ("initialize".equals(method)) {
                JSONObject info = new JSONObject();
                info.put("name", "Radare2Blutter MCP");
                info.put("version", "1.0.0");
                JSONObject res = new JSONObject();
                res.put("protocolVersion", PROTOCOL);
                res.put("serverInfo", info);
                res.put("capabilities", new JSONObject().put("tools", new JSONObject()));
                return rpcResult(id, res);
            }
            if ("tools/list".equals(method)) {
                JSONObject res = new JSONObject();
                res.put("tools", buildToolList());
                return rpcResult(id, res);
            }
            if ("tools/call".equals(method)) {
                JSONObject params = req.optJSONObject("params");
                String toolName = params != null ? params.optString("name", "") : "";
                JSONObject args = params != null ? params.optJSONObject("arguments") : null;

                // 配了 Python 后端就转发；否则本机真实执行
                if (backendUrl != null && backendUrl.length() > 0) {
                    String f = forward(raw);
                    if (f != null) return f;
                }
                log("调用工具 " + toolName);
                String result = executor.execute(toolName, args);
                JSONObject res = new JSONObject();
                try {
                    res.put("content", new JSONArray()
                            .put(new JSONObject().put("type", "text").put("text", result)));
                    res.put("isError", false);
                } catch (Exception e) {
                    return rpcError(id, -32603, "结果封装失败: " + e.getMessage());
                }
                return rpcResult(id, res);
            }
            if ("ping".equals(method)) {
                return rpcResult(id, new JSONObject());
            }
            return rpcError(id, -32601, "不支持的方法: " + method);
        } catch (Exception e) {
            return rpcError(id, -32700, "解析失败: " + e.getMessage());
        }
    }

    /** 低价值日志：只进内存缓冲，不刷到 UI。 */
    private void logDebug(String m) {
        if (m == null) return;
        if (android.os.Build.VERSION.SDK_INT >= 17) {
            android.util.Log.d("R2B_MCP", m);
        }
        if (logBuf != null) logBuf.append("\n").append(m);
    }

    private void handle(Socket sock) {
        try {
            sock.setSoTimeout(15000);
            InputStream is = sock.getInputStream();
            OutputStream os = sock.getOutputStream();

            // 读请求头
            StringBuilder head = new StringBuilder();
            int b;
            while ((b = is.read()) != -1) {
                head.append((char) b);
                if (head.length() > 4
                        && head.substring(head.length() - 4).equals("\r\n\r\n")) {
                    break;
                }
                if (head.length() > 8192) break;
            }
            String h = head.toString();
            String line = h.length() > 0 ? h.split("\r\n")[0] : "";
            String upper = line.toUpperCase();

            int len = 0;
            String[] ls = h.split("\r\n");
            for (String s : ls) {
                if (s.toLowerCase().startsWith("content-length:")) {
                    try {
                        len = Integer.parseInt(s.substring(s.indexOf(':') + 1).trim());
                    } catch (Exception ignored) {
                    }
                }
            }

            byte[] bodyBytes = new byte[0];
            if (len > 0) {
                bodyBytes = new byte[len];
                int off = 0;
                while (off < len) {
                    int r = is.read(bodyBytes, off, len - off);
                    if (r <= 0) break;
                    off += r;
                }
            }
            String rawBody = new String(bodyBytes, Charset.forName("UTF-8"));

            String respBody;
            int status;
            if (upper.startsWith("OPTIONS")) {
                respBody = "";
                status = 204;
            } else if (upper.startsWith("GET")) {
                JSONObject o = new JSONObject();
                o.put("name", "Radare2Blutter MCP");
                o.put("protocolVersion", PROTOCOL);
                o.put("tools", toolCount());
                o.put("backend", backendUrl == null ? "" : backendUrl);
                o.put("endpoints", new JSONArray().put("/mcp").put("/health"));
                respBody = o.toString();
                status = 200;
            } else if (upper.startsWith("POST")) {
                respBody = dispatch(rawBody);
                status = 200;
            } else {
                respBody = "{\"error\":\"method not allowed\"}";
                status = 405;
            }

            byte[] out = respBody.getBytes("UTF-8");
            StringBuilder sb = new StringBuilder();
            sb.append("HTTP/1.1 ").append(status);
            sb.append(status == 200 ? " OK" : (status == 204 ? " No Content" : " Error"));
            sb.append("\r\n");
            sb.append("Content-Type: application/json; charset=utf-8\r\n");
            sb.append("Content-Length: ").append(out.length).append("\r\n");
            sb.append("Access-Control-Allow-Origin: *\r\n");
            sb.append("Access-Control-Allow-Methods: POST, GET, OPTIONS\r\n");
            sb.append("Access-Control-Allow-Headers: Content-Type, Mcp-Session-Id\r\n");
            sb.append("Connection: close\r\n\r\n");
            os.write(sb.toString().getBytes("UTF-8"));
            os.write(out);
            os.flush();
        } catch (Exception e) {
            // 客户端提前断开（Broken pipe / Connection reset）是常态：
            // 探测连接、客户端超时、切后台都会发生。它不是服务端故障，
            // 不该刷成错误日志，否则日志区全是噪音盖掉真问题。
            String m = e.getMessage() == null ? e.getClass().getSimpleName() : e.getMessage();
            if (m.contains("Broken pipe") || m.contains("Connection reset")
                    || m.contains("ECONNRESET") || m.contains("EPIPE")) {
                logDebug("客户端断开: " + m);
            } else {
                log("处理请求异常: " + m);
            }
        } finally {
            try {
                sock.close();
            } catch (Exception ignored) {
            }
        }
    }
}
