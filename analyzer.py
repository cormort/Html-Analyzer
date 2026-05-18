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

@dataclass
class FunctionInfo:
    name: str
    start_line: int
    end_line: int
    calls: Set[str] = field(default_factory=set)
    side_effects: Set[str] = field(default_factory=set)
    reads: Set[str] = field(default_factory=set)   # 讀取的變數
    writes: Set[str] = field(default_factory=set)  # 寫入的變數

@dataclass
class ReportData:
    html_file: str
    warnings: List[str] = field(default_factory=list)
    functions: Dict[str, FunctionInfo] = field(default_factory=dict)

class HTMLJSAnalyzer:
    def __init__(self, html_path: str):
        self.html_path = html_path
        self.parser = get_parser('javascript')
        self.report = ReportData(html_file=os.path.basename(html_path))
        self.script_blocks = [] # (start_line, script_content)

    def analyze(self) -> ReportData:
        self._parse_html()
        self._analyze_js()
        return self.report

    def _parse_html(self):
        with open(self.html_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()
            html_content = "".join(lines)
            
        soup = BeautifulSoup(html_content, 'html.parser')
        
        # 整檔警告收集
        for script in soup.find_all('script'):
            if script.get('src'):
                self.report.warnings.append(f"外部 script 引用：{script.get('src')}")
            elif script.string:
                # 尋找 script 所在的行號 (Best effort approximation)
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
            
        # 簡單的 inline handler 偵測 (如 onclick)
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
        
        # 識別函式定義
        if node.type in ['function_declaration', 'function_expression', 'arrow_function', 'method_definition']:
            name_node = None
            if node.type == 'function_declaration' or node.type == 'method_definition':
                name_node = node.child_by_field_name('name')
            elif node.parent and node.parent.type == 'variable_declarator':
                name_node = node.parent.child_by_field_name('name')
            
            # 若無名稱則標記為匿名 (注意：移除了會破壞 Mermaid 的角括號 < >)
            name = name_node.text.decode('utf8') if name_node else f"anonymous@{offset_line + node.start_point[0]}:{node.start_point[1]}"
            
            func_name = name
            if func_name not in self.report.functions:
                self.report.functions[func_name] = FunctionInfo(
                    name=func_name,
                    start_line=offset_line + node.start_point[0],
                    end_line=offset_line + node.end_point[0]
                )

        # 如果在函式內部，分析 CallExpression、副作用與變數操作
        if current_func and current_func in self.report.functions:
            func_info = self.report.functions[current_func]
            
            # 1. 紀錄函式呼叫
            if node.type == 'call_expression':
                callee = node.child_by_field_name('function')
                if callee:
                    callee_name = callee.text.decode('utf8').split('.')[-1]
                    func_info.calls.add(callee_name)
                    
            # 2. 檢查副作用 (識別字比對)
            if node.type in ['identifier', 'property_identifier']:
                token = node.text.decode('utf8')
                for category, identifiers in SIDE_EFFECTS_MAP.items():
                    if token in identifiers:
                        func_info.side_effects.add(category)

            # 3. 資料流：變數宣告 (let x = y)
            if node.type == 'variable_declarator':
                lhs = node.child_by_field_name('name')
                rhs = node.child_by_field_name('value')
                if lhs and lhs.type == 'identifier':
                    func_info.writes.add(lhs.text.decode('utf8'))
                if rhs:
                    self._extract_identifiers_as_reads(rhs, func_info)

            # 4. 資料流：賦值操作 (x = y 或 obj.x = y)
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

            # 5. 資料流：單純的變數使用 (當作讀取)
            elif node.type == 'identifier' and node.parent and node.parent.type not in ['function_declaration', 'variable_declarator', 'property_identifier', 'member_expression']:
                var_name = node.text.decode('utf8')
                # 排除常見的全域關鍵字與內建函式，減少雜訊
                ignore_list = {'console', 'window', 'document', 'Math', 'JSON', 'undefined', 'null', 'true', 'false'}
                if var_name not in ignore_list:
                    func_info.reads.add(var_name)

        for child in node.children:
            self._traverse_ast(child, offset_line, func_name)

    def _extract_identifiers_as_reads(self, node, func_info):
        """輔助函式：遞迴抓取 RHS 中的變數名稱當作 Read"""
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
        
        # --- 雜訊過濾機制 ---
        cleaned_functions = {}
        for name, func in report.functions.items():
            is_anonymous = name.startswith("anonymous@")
            has_effects = len(func.side_effects) > 0
            has_calls = len(func.calls) > 0
            
            # 條件：如果是匿名函式，且「沒有副作用」也「沒有呼叫其他函式」，就當作雜訊丟棄
            if is_anonymous and not has_effects and not has_calls:
                continue
                
            cleaned_functions[name] = func
            
        # 將過濾後的乾淨清單存回 report
        report.functions = cleaned_functions
        self.report = report

    def write_markdown(self):
        path = os.path.join(self.output_dir, f"{self.base_name}.report.md")
        side_effect_funcs = [f for f in self.report.functions.values() if f.side_effects]
        
        lines = [
            f"# 分析報告：{self.report.html_file}",
            "\n## 整體摘要",
            f"- 函式總數：{len(self.report.functions)}",
            f"- 含副作用函式：**{len(side_effect_funcs)}**",
            f"- 整檔警告：{len(self.report.warnings)}",
        ]

        if self.report.warnings:
            lines.append("\n## 整檔警告")
            for w in self.report.warnings:
                lines.append(f"- ⚠️ **{w}**")

        lines.append("\n## 函式清單")
        for func in self.report.functions.values():
            icon_str = "".join([self.icons.get(se, "") for se in func.side_effects])
            
            # 針對有副作用的函式加上醒目標示
            if func.side_effects:
                lines.append(f"\n### 🚨 <mark>{icon_str} {func.name} (含風險)</mark>")
            else:
                lines.append(f"\n### {func.name}")
                
            lines.append(f"- 位置：第 {func.start_line}-{func.end_line} 行")
            
            calls = ", ".join(func.calls) if func.calls else "無"
            lines.append(f"- 呼叫：{calls}")
            
            reads = ", ".join(func.reads) if func.reads else "無"
            writes = ", ".join(func.writes) if func.writes else "無"
            lines.append(f"- 讀取變數：{reads}")
            lines.append(f"- 寫入變數：{writes}")
            
            # 凸顯副作用文字
            if func.side_effects:
                effects = ", ".join(func.side_effects)
                lines.append(f"- **副作用：{effects}** ⚠️")
            else:
                lines.append(f"- 副作用：無")
            
            callers = [f.name for f in self.report.functions.values() if func.name in f.calls]
            caller_str = ", ".join(callers) if callers else "無"
            lines.append(f"- 被誰呼叫：{caller_str}")

        lines.append("\n---\n*免責聲明：此工具僅為輔助審查用途，基於靜態分析，無法保證偵測所有動態行為或繞過手法。*")
        
        with open(path, 'w', encoding='utf-8') as f:
            f.write("\n".join(lines))

    def write_mermaid(self):
        path = os.path.join(self.output_dir, f"{self.base_name}.flow.mmd")
        lines = ["flowchart TD"]
        
        # 輔助函式：確保 ID 不含 Mermaid 不允許的特殊符號
        import re
        def sanitize_id(name):
            return re.sub(r'[^a-zA-Z0-9]', '_', name)
            
        def sanitize_label(name):
            return name.replace('<', '&lt;').replace('>', '&gt;')
        
        for func in self.report.functions.values():
            # 使用清理過的 ID 建立節點
            safe_id = sanitize_id(func.name)
            safe_label = sanitize_label(func.name)
            
            node_def = f'    {safe_id}["{safe_label}()"]'
            
            if func.side_effects:
                primary_class = list(func.side_effects)[0]
                node_def += f":::{primary_class}"
            lines.append(node_def)
            
            # 1. 建立控制流連線 (實線：A 呼叫 B)
            for call in func.calls:
                if call in self.report.functions:
                    safe_call_id = sanitize_id(call)
                    lines.append(f"    {safe_id} --> {safe_call_id}")

        # 2. 建立資料流連線 (虛線：A 寫入某變數，B 讀取該變數)
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
                    if writer.name != reader.name: # 避免自己連自己
                        w_id = sanitize_id(writer.name)
                        r_id = sanitize_id(reader.name)
                        lines.append(f"    {w_id} -.->|變數: {var_name}| {r_id}")

        # 增加框線厚度與樣式
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