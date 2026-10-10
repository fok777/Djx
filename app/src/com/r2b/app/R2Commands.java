package com.r2b.app;

/**
 * radare2 工具名 → r2 命令的映射表。
 *
 * 为什么是"表"而不是 switch-case：
 *   radare2 本身是一个完整的命令解释器，r_core_cmd_str 能吃几百条命令。
 *   黑猫那 94 个 R2_* 工具，本质是给 r2 命令套了个语义化的壳：
 *     R2_Analyze → aaa      R2_Functions → afl      R2_Symbols → is
 *   所以正确做法是从引擎命令**批量派生**，而不是一个个手写分支。
 *   之前用 switch 只覆盖了 8 个，其余全落到 default("?V")，
 *   对外却宣称 94 个——这就是"空壳"的来源。
 *
 * 底层调用链只有一条：Radare2Bridge.cmd(命令)，全部真跑。
 */
public final class R2Commands {

    private R2Commands() {}

    /** 工具名 → r2 命令模板。%s 由同名参数填充。 */
    private static final String[][] MAP = {
        // ---- 分析 ----
        {"R2_Analyze",                 "aaa"},
        {"R2_Analyze_File",            "af"},
        {"R2_Analyze_Target",          "aa"},
        {"R2_Analysis_Hints",          "ah"},
        {"R2_Functions",               "afl"},
        {"R2_Blocks",                  "afb"},
        {"R2_Arch",                    "iA"},
        {"R2_Signatures",              "z"},
        {"R2_Zignatures",              "z"},

        // ---- 信息 ----
        {"R2_Info",                    "iI"},
        {"R2_Entries",                 "ie"},
        {"R2_Exports",                 "iE"},
        {"R2_Imports",                 "ii"},
        {"R2_Sections",                "iS"},
        {"R2_Symbols",                 "is"},
        {"R2_Strings",                 "iz"},
        {"R2_Globals",                 "is~GLOBAL"},
        {"R2_Reload",                  "oo"},
        {"R2_Close",                   "o-*"},
        {"R2_Open",                    "o %s"},

        // ---- 反汇编 / 伪码 ----
        {"R2_Disassemble",             "pdf"},
        {"R2_Decompile_Function",      "pdc"},
        {"R2_Get_PseudoC",             "pdc"},
        {"R2_PseudoC_Status",          "e asm.pseudo"},
        {"R2_Export_PseudoC_To_File",  "pdc"},

        // ---- 打印 / 读取 ----
        {"R2_Hexdump",                 "px"},
        {"R2_Bytes_Read",              "p8 %s"},
        {"R2_Bytes_Write",             "w %s"},
        {"R2_Patch",                   "w %s"},
        {"R2_Yank",                    "y"},
        {"R2_Calculate",               "? %s"},
        {"R2_Hash",                    "ph %s"},
        {"R2_Map",                     "om"},
        {"R2_Seek",                    "s %s"},
        {"R2_Goto",                    "s %s"},

        // ---- 交叉引用 ----
        {"R2_Xrefs",                   "axt"},
        {"R2_Manage_Xrefs",            "ax"},

        // ---- 搜索 ----
        {"R2_Search",                  "/ %s"},
        {"R2_Search_String",           "/ %s"},
        {"R2_Search_Functions",        "afl~%s"},
        {"R2_Search_PseudoC",          "pdc~%s"},

        // ---- 类型 / 结构 ----
        {"R2_Structs",                 "ts"},
        {"R2_Types",                   "t"},
        {"R2_Format_Parse",            "pf"},

        // ---- 配置 / 杂项 ----
        {"R2_Config_Manager",          "e"},
        {"R2_Alias",                   "$"},
        {"R2_Macros",                  "(?*"},
        {"R2_Sdb_Query",               "k %s"},
        {"R2_Shellcode",               "gs"},
        {"R2_Debugger",                "d"},
        {"R2_Diff",                    "c?"},
        {"R2_Leak",                    "db"},
        {"R2_List_Sessions",           "o"},
        {"R2_Text_Log",                "?"},
        {"R2_Panel_Hint",              "?"},
        {"R2_Cmd",                     "%s"},
        {"R2_Version",                 "?V"},
    };

    /**
     * 关键词定位系列：R2_Locate_<Keyword> 共 30+ 个，
     * 本质都是在二进制里搜对应语义的字符串/符号。
     * 黑猫把它们做成独立工具方便 AI 直接点，底层就是一次搜索。
     */
    private static final String[][] LOCATE = {
        {"R2_Locate_Activated","activated"}, {"R2_Locate_Ammo","ammo"},
        {"R2_Locate_Auth","auth"},           {"R2_Locate_Buy","buy"},
        {"R2_Locate_Bypass","bypass"},       {"R2_Locate_Coin","coin"},
        {"R2_Locate_Damage","damage"},       {"R2_Locate_Debug","debug"},
        {"R2_Locate_Experience","experience"},{"R2_Locate_Expire","expire"},
        {"R2_Locate_Flag","flag"},           {"R2_Locate_Gold","gold"},
        {"R2_Locate_Health","health"},       {"R2_Locate_HideAd","hidead"},
        {"R2_Locate_IsMember","ismember"},   {"R2_Locate_IsVip","isvip"},
        {"R2_Locate_License","license"},     {"R2_Locate_LoadAd","loadad"},
        {"R2_Locate_Member","member"},       {"R2_Locate_Pay","pay"},
        {"R2_Locate_Premium","premium"},     {"R2_Locate_Price","price"},
        {"R2_Locate_Prod","prod"},           {"R2_Locate_Purchase","purchase"},
        {"R2_Locate_Rate","rate"},           {"R2_Locate_Root","root"},
        {"R2_Locate_Secret","secret"},       {"R2_Locate_Serial","serial"},
        {"R2_Locate_ShowAd","showad"},       {"R2_Locate_Subscribe","subscribe"},
        {"R2_Locate_Test","test"},           {"R2_Locate_Token","token"},
        {"R2_Locate_Trial","trial"},         {"R2_Locate_Unlock","unlock"},
        {"R2_Locate_Verify","verify"},       {"R2_Locate_Vip","vip"},
        {"R2_To_Ub_Call",""},
    };

    /**
     * 取某工具对应的 r2 命令。
     * @return null 表示本表不覆盖（交给上层兜底）
     */
    public static String commandFor(String tool, String arg) {
        for (String[] row : MAP) {
            if (row[0].equals(tool)) {
                String tpl = row[1];
                if (tpl.contains("%s")) {
                    return tpl.replace("%s", arg == null ? "" : arg.trim());
                }
                // 模板无占位符但传了参数，拼在后面（如 R2_Strings + 关键词）
                return (arg == null || arg.trim().isEmpty()) ? tpl : tpl + " " + arg.trim();
            }
        }
        for (String[] row : LOCATE) {
            if (row[0].equals(tool)) {
                String kw = (arg == null || arg.trim().isEmpty()) ? row[1] : arg.trim();
                return "iz~" + kw;
            }
        }
        return null;
    }

    /** 统计本表覆盖的工具数。 */
    public static int coverage() { return MAP.length + LOCATE.length; }

    /** 本表覆盖的全部工具名，用于自检。 */
    public static String[] covered() {
        String[] out = new String[MAP.length + LOCATE.length];
        int i = 0;
        for (String[] r : MAP) out[i++] = r[0];
        for (String[] r : LOCATE) out[i++] = r[0];
        return out;
    }
}
