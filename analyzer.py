# analyzer.py
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
            
            # 若無名稱則標記為匿名
            name = name_node.text.decode('utf8') if name_node else f"<anonymous@{offset_line + node.start_point[0]}:{node.start_point[1]}>"
            
            func_name = name
            if func_name not in self.report.functions:
                self.report.functions[func_name] = FunctionInfo(
                    name=func_name,
                    start_line=offset_line + node.start_point[0],
                    end_line=offset_line + node.end_point[0]
                )

        # 如果在函式內部，分析 CallExpression 和 副作用
        if current_func and current_func in self.report.functions:
            if node.type == 'call_expression':
                callee = node.child_by_field_name('function')
                if callee:
                    callee_name = callee.text.decode('utf8').split('.')[-1]
                    self.report.functions[current_func].calls.add(callee_name)
                    
            # 檢查副作用 (識別字比對)
            if node.type in ['identifier', 'property_identifier']:
                token = node.text.decode('utf8')
                for category, identifiers in SIDE_EFFECTS_MAP.items():
                    if token in identifiers:
                        self.report.functions[current_func].side_effects.add(category)

        for child in node.children:
            self._traverse_ast(child, offset_line, func_name)

class Exporter:
    def __init__(self, report: ReportData, output_dir: str, base_name: str):
        self.report = report
        self.output_dir = output_dir
        self.base_name = base_name
        self.icons = {
            "network": "🌐", "execution": "⚡", "dom": "💉",
            "storage": "🗄️", "sensitive": "📋", "dynamic": "🔗"
        }

    def write_markdown(self):
        path = os.path.join(self.output_dir, f"{self.base_name}.report.md")
        side_effect_funcs = [f for f in self.report.functions.values() if f.side_effects]
        
        lines = [
            f"# 分析報告：{self.report.html_file}",
            "\n## 整體摘要",
            f"- 函式總數：{len(self.report.functions)}",
            f"- 含副作用函式：{len(side_effect_funcs)}",
            f"- 整檔警告：{len(self.report.warnings)}",
        ]

        if self.report.warnings:
            lines.append("\n## 整檔警告")
            for w in self.report.warnings:
                lines.append(f"- ⚠️ {w}")

        lines.append("\n## 函式清單")
        for func in self.report.functions.values():
            icon_str = "".join([self.icons.get(se, "") for se in func.side_effects])
            lines.append(f"\n### {icon_str} {func.name}")
            lines.append(f"- 位置：第 {func.start_line}-{func.end_line} 行")
            
            calls = ", ".join(func.calls) if func.calls else "無"
            lines.append(f"- 呼叫：{calls}")
            
            effects = ", ".join(func.side_effects) if func.side_effects else "無"
            lines.append(f"- 副作用：{effects}")
            
            callers = [f.name for f in self.report.functions.values() if func.name in f.calls]
            caller_str = ", ".join(callers) if callers else "無"
            lines.append(f"- 被誰呼叫：{caller_str}")

        lines.append("\n---\n*免責聲明：此工具僅為輔助審查用途，基於靜態分析，無法保證偵測所有動態行為或繞過手法。*")
        
        with open(path, 'w', encoding='utf-8') as f:
            f.write("\n".join(lines))

    def write_mermaid(self):
        path = os.path.join(self.output_dir, f"{self.base_name}.flow.mmd")
        lines = ["flowchart TD"]
        
        for func in self.report.functions.values():
            # 定義節點與樣式類別
            classes = ",".join(func.side_effects)
            node_def = f'    {func.name}["{func.name}()"]'
            if classes:
                # 簡單取第一個副作用做為主要顏色標記
                primary_class = list(func.side_effects)[0]
                node_def += f":::{primary_class}"
            lines.append(node_def)
            
            # 定義連線
            for call in func.calls:
                # 僅繪製有在本地定義的函式關係，減少雜訊
                if call in self.report.functions:
                    lines.append(f"    {func.name} --> {call}")

        # 加入樣式定義
        lines.extend([
            "",
            "    classDef network fill:#fee,stroke:#c00",
            "    classDef execution fill:#fee,stroke:#c00",
            "    classDef dom fill:#fef,stroke:#90c",
            "    classDef storage fill:#eef,stroke:#36c",
            "    classDef sensitive fill:#ffe,stroke:#c90",
            "    classDef dynamic fill:#efe,stroke:#090"
        ])
        
        with open(path, 'w', encoding='utf-8') as f:
            f.write("\n".join(lines))
