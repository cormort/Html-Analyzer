import os
import re
from dataclasses import dataclass, field
from typing import List, Dict, Set
from bs4 import BeautifulSoup
from tree_sitter_languages import get_parser

# 副作用識別字對照表
SIDE_EFFECTS_MAP = {
    "network": {"fetch", "XMLHttpRequest", "WebSocket", "sendBeacon", "EventSource"},
    "execution": {"eval", "Function", "setTimeout", "setInterval"},
    "dom": {"innerHTML", "outerHTML", "write", "insertAdjacentHTML"},
    "storage": {"localStorage", "sessionStorage", "indexedDB", "cookie"},
    "sensitive": {"clipboard", "geolocation", "getUserMedia"},
    "dynamic": {"import"}
}

# 內建無害方法白名單 (不列入主要呼叫關聯)
BUILTIN_METHODS = {
    'forEach', 'map', 'filter', 'reduce', 'push', 'pop', 'shift', 'unshift', 'splice',
    'addEventListener', 'removeEventListener',
    'add', 'remove', 'toggle', 'contains', 
    'getAttribute', 'setAttribute', 'querySelector', 'querySelectorAll', 'getElementById', 'getElementsByClassName',
    'includes', 'indexOf', 'split', 'join', 'replace', 'trim'
}

@dataclass
class FunctionInfo:
    name: str
    start_line: int
    end_line: int
    calls: Set[str] = field(default_factory=set)
    builtins: Set[str] = field(default_factory=set) # 新增：記錄呼叫了哪些內建方法
    side_effects: Set[str] = field(default_factory=set)
    reads: Set[str] = field(default_factory=set)
    writes: Set[str] = field(default_factory=set)

@dataclass
class ReportData:
    html_file: str
    warnings: List[str] = field(default_factory=list)
    functions: Dict[str, FunctionInfo] = field(default_factory=dict)
    ui_functions: Dict[str, FunctionInfo] = field(default_factory=dict) # 新增：存放純 UI 腳本

class HTMLJSAnalyzer:
    def __init__(self, html_path: str):
        self.html_path = html_path
        self.parser = get_parser('javascript')
        self.report = ReportData(html_file=os.path.basename(html_path))
        self.script_blocks = []

    def analyze(self) -> ReportData:
        self._parse_html()
        self._analyze_js()
        return self.report

    def _parse_html(self):
        with open(self.html_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()
            html_content = "".join(lines)
            
        soup = BeautifulSoup(html_content, 'html.parser')
        
        for script in soup.find_all('script'):
            if script.get('src'):
                self.report.warnings.append(f"外部 script 引用：{script.get('src')}")
            elif script.string:
                start_line = 1
                for i, line in enumerate(lines):
                    if "<script" in line.lower() and script.string.strip()[:20] in line:
                        start_line = i + 1
                        break
                self.script_blocks.append((start_line, script.string))

        if soup.find_all('iframe'):
            for iframe in soup.find_all('iframe'):
                self.report.warnings.append(f"發現 iframe 標籤 (src: {iframe.get('src')})")
        
        if soup.find('meta', attrs={'http-equiv': lambda x: x and x.lower() == 'refresh'}):
            self.report.warnings.append("發現 <meta http-equiv=\"refresh\"> (自動跳轉)")
            
        inline_handler_pattern = re.compile(r'^on[a-z]+$')
        for tag in soup.find_all(True):
            for attr in tag.attrs:
                if inline_handler_pattern.match(attr):
                    self.report.warnings.append(f"發現 inline event handler: {attr} 於 <{tag.name}>")
                    break

    def _analyze_js(self):
        for offset_line, js_code in self.script_blocks:
            tree = self.parser.parse(bytes(js_code, "utf8"))
            self._traverse_ast(tree.root_node, offset_line)

    def _traverse_ast(self, node, offset_line, current_func=None):
        func_name = current_func
        
        if node.type in ['function_declaration', 'function_expression', 'arrow_function', 'method_definition']:
            name_node = None
            if node.type == 'function_declaration' or node.type == 'method_definition':
                name_node = node.child_by_field_name('name')
            elif node.parent and node.parent.type == 'variable_declarator':
                name_node = node.parent.child_by_field_name('name')
            
            name = name_node.text.decode('utf8') if name_node else f"anonymous@{offset_line + node.start_point[0]}:{node.start_point[1]}"
            
            func_name = name
            if func_name not in self.report.functions:
                self.report.functions[func_name] = FunctionInfo(
                    name=func_name,
                    start_line=offset_line + node.start_point[0],
                    end_line=offset_line + node.end_point[0]
                )

        if current_func and current_func in self.report.functions:
            func_info = self.report.functions[current_func]
            
            # 🔥 將呼叫分為「主邏輯」與「內建白名單」
            if node.type == 'call_expression':
                callee = node.child_by_field_name('function')
                if callee:
                    callee_name = callee.text.decode('utf8').split('.')[-1]
                    if callee_name in BUILTIN_METHODS:
                        func_info.builtins.add(callee_name)
                    else:
                        func_info.calls.add(callee_name)
                    
            if node.type in ['identifier', 'property_identifier']:
                token = node.text.decode('utf8')
                for category, identifiers in SIDE_EFFECTS_MAP.items():
                    if token in identifiers:
                        func_info.side_effects.add(category)

            if node.type == 'variable_declarator':
                lhs = node.child_by_field_name('name')
                rhs = node.child_by_field_name('value')
                if lhs and lhs.type == 'identifier':
                    func_info.writes.add(lhs.text.decode('utf8'))
                if rhs:
                    self._extract_identifiers_as_reads(rhs, func_info)

            elif node.type == 'assignment_expression':
                lhs = node.child_by_field_name('left')
                rhs = node.child_by_field_name('right')
                if lhs:
                    if lhs.type == 'identifier':
                        func_info.writes.add(lhs.text.decode('utf8'))
                    elif lhs.type == 'member_expression':
                        obj = lhs.child_by_field_name('object')
                        if obj and obj.type == 'identifier':
                            func_info.writes.add(obj.text.decode('utf8'))
                if rhs:
                    self._extract_identifiers_as_reads(rhs, func_info)

            elif node.type == 'identifier' and node.parent and node.parent.type not in ['function_declaration', 'variable_declarator', 'property_identifier', 'member_expression']:
                var_name = node.text.decode('utf8')
                ignore_list = {'console', 'window', 'document', 'Math', 'JSON', 'undefined', 'null', 'true', 'false', 'e', 'event'}
                if var_name not in ignore_list:
                    func_info.reads.add(var_name)

        for child in node.children:
            self._traverse_ast(child, offset_line, func_name)

    def _extract_identifiers_as_reads(self, node, func_info):
        if node.type == 'identifier':
            var_name = node.text.decode('utf8')
            ignore_list = {'console', 'window', 'document', 'Math', 'JSON', 'undefined', 'null'}
            if var_name not in ignore_list:
                func_info.reads.add(var_name)
        for child in node.children:
            self._extract_identifiers_as_reads(child, func_info)


class Exporter:
    def __init__(self, report: ReportData, output_dir: str, base_name: str):
        self.output_dir = output_dir
        self.base_name = base_name
        self.icons = {
            "network": "🌐", "execution": "⚡", "dom": "💉",
            "storage": "🗄️", "sensitive": "📋", "dynamic": "🔗"
        }
        
        # --- 🔥 分流機制：將純 UI/狀態腳本抽離 ---
        main_funcs = {}
        ui_funcs = {}
        
        for name, func in report.functions.items():
            is_anonymous = name.startswith("anonymous@")
            has_effects = len(func.side_effects) > 0
            has_custom_calls = len(func.calls) > 0
            has_activity = len(func.builtins) > 0 or len(func.reads) > 0 or len(func.writes) > 0
            
            # 如果是匿名函式、沒有危險副作用、也沒有呼叫其他自訂函式
            if is_anonymous and not has_effects and not has_custom_calls:
                if has_activity:
                    ui_funcs[name] = func # 歸類為 UI/常規腳本
                else:
                    continue # 完全空的函式，直接丟棄 (雜訊)
            else:
                main_funcs[name] = func # 歸類為主邏輯
                
        report.functions = main_funcs
        report.ui_functions = ui_funcs
        self.report = report

    def write_markdown(self):
        # 產出主報告
        path_main = os.path.join(self.output_dir, f"{self.base_name}.report.md")
        side_effect_funcs = [f for f in self.report.functions.values() if f.side_effects]
        
        lines = [
            f"# 分析報告：{self.report.html_file}",
            "\n## 整體摘要 (主邏輯)",
            f"- 函式總數：{len(self.report.functions)}",
            f"- 含副作用函式：**{len(side_effect_funcs)}**",
            f"- UI/常規輔助函式：{len(self.report.ui_functions)} (見獨立頁籤)",
        ]

        if self.report.warnings:
            lines.append("\n## 整檔警告")
            for w in self.report.warnings:
                lines.append(f"- ⚠️ **{w}**")

        lines.append("\n## 主函式清單")
        self._append_function_details(lines, self.report.functions)
        
        with open(path_main, 'w', encoding='utf-8') as f:
            f.write("\n".join(lines))
            
        # 產出 UI 報告
        path_ui = os.path.join(self.output_dir, f"{self.base_name}.ui_report.md")
        lines_ui = ["# 常規腳本 (UI/狀態操作)\n"]
        if not self.report.ui_functions:
            lines_ui.append("*未偵測到純常規 UI 腳本。*")
        else:
            lines_ui.append("> 此區塊列出僅包含內建方法 (如 `forEach`, `addEventListener`, `classList.add`)，且無危險副作用的匿名函式。\n")
            self._append_function_details(lines_ui, self.report.ui_functions)
            
        with open(path_ui, 'w', encoding='utf-8') as f:
            f.write("\n".join(lines_ui))

    def _append_function_details(self, lines, func_dict):
        for func in func_dict.values():
            icon_str = "".join([self.icons.get(se, "") for se in func.side_effects])
            
            if func.side_effects:
                lines.append(f"\n### 🚨 <mark>{icon_str} {func.name} (含風險)</mark>")
            else:
                lines.append(f"\n### {func.name}")
                
            lines.append(f"- 位置：第 {func.start_line}-{func.end_line} 行")
            
            calls = ", ".join(func.calls) if func.calls else "無"
            builtins = ", ".join(func.builtins) if func.builtins else "無"
            lines.append(f"- 呼叫函式：{calls}")
            lines.append(f"- 內建方法：{builtins}")
            
            reads = ", ".join(func.reads) if func.reads else "無"
            writes = ", ".join(func.writes) if func.writes else "無"
            lines.append(f"- 讀取變數：{reads}")
            lines.append(f"- 寫入變數：{writes}")
            
            if func.side_effects:
                effects = ", ".join(func.side_effects)
                lines.append(f"- **副作用：{effects}** ⚠️")
            else:
                lines.append(f"- 副作用：無")
            
            callers = [f.name for f in self.report.functions.values() if func.name in f.calls]
            caller_str = ", ".join(callers) if callers else "無"
            lines.append(f"- 被誰呼叫：{caller_str}")

    def write_mermaid(self):
        path = os.path.join(self.output_dir, f"{self.base_name}.flow.mmd")
        lines = ["flowchart TD"]
        
        import re
        def sanitize_id(name):
            return re.sub(r'[^a-zA-Z0-9]', '_', name)
        def sanitize_label(name):
            return name.replace('<', '&lt;').replace('>', '&gt;')
        
        for func in self.report.functions.values():
            safe_id = sanitize_id(func.name)
            safe_label = sanitize_label(func.name)
            node_def = f'    {safe_id}["{safe_label}()"]'
            
            if func.side_effects:
                primary_class = list(func.side_effects)[0]
                node_def += f":::{primary_class}"
            lines.append(node_def)
            
            for call in func.calls:
                if call in self.report.functions:
                    safe_call_id = sanitize_id(call)
                    lines.append(f"    {safe_id} --> {safe_call_id}")

        all_writes = set()
        all_reads = set()
        for f in self.report.functions.values():
            all_writes.update(f.writes)
            all_reads.update(f.reads)
            
        shared_vars = all_writes.intersection(all_reads)
        
        for var_name in shared_vars:
            writers = [f for f in self.report.functions.values() if var_name in f.writes]
            readers = [f for f in self.report.functions.values() if var_name in f.reads]
            for writer in writers:
                for reader in readers:
                    if writer.name != reader.name: 
                        w_id = sanitize_id(writer.name)
                        r_id = sanitize_id(reader.name)
                        lines.append(f"    {w_id} -.->|變數: {var_name}| {r_id}")

        lines.extend([
            "",
            "    classDef network fill:#fee,stroke:#c00,stroke-width:3px,color:#000",
            "    classDef execution fill:#fee,stroke:#c00,stroke-width:3px,color:#000",
            "    classDef dom fill:#fef,stroke:#90c,stroke-width:3px,color:#000",
            "    classDef storage fill:#eef,stroke:#36c,stroke-width:3px,color:#000",
            "    classDef sensitive fill:#ffe,stroke:#c90,stroke-width:3px,color:#000",
            "    classDef dynamic fill:#efe,stroke:#090,stroke-width:3px,color:#000"
        ])
        
        with open(path, 'w', encoding='utf-8') as f:
            f.write("\n".join(lines))