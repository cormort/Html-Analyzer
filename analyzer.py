import os
import re
import sys
import logging
from dataclasses import dataclass, field
from typing import List, Dict, Set
from bs4 import BeautifulSoup
from tree_sitter_languages import get_parser
from tree_sitter import Node as TSNode
from mermaid_gen import generate_mermaid_flowchart
from sbom import analyze_dependencies, Dependency, SEVERITY_ICONS, get_db_metadata

logging.basicConfig(level=logging.WARNING)

SIDE_EFFECTS_MAP = {
    "network": {"fetch", "XMLHttpRequest", "WebSocket", "sendBeacon", "EventSource"},
    "execution": {"eval", "Function", "setTimeout", "setInterval"},
    "dom": {"innerHTML", "outerHTML", "write", "insertAdjacentHTML"},
    "storage": {"localStorage", "sessionStorage", "indexedDB", "cookie"},
    "sensitive": {"clipboard", "geolocation", "getUserMedia"},
    "dynamic": {"import"}
}

SIDE_EFFECTS_REVERSE: Dict[str, str] = {}
for _cat, _idents in SIDE_EFFECTS_MAP.items():
    for _id in _idents:
        SIDE_EFFECTS_REVERSE[_id] = _cat

BUILTIN_METHODS = {
    'forEach', 'map', 'filter', 'reduce', 'push', 'pop', 'shift', 'unshift', 'splice',
    'addEventListener', 'removeEventListener',
    'add', 'remove', 'toggle', 'contains',
    'getAttribute', 'setAttribute', 'querySelector', 'querySelectorAll', 'getElementById', 'getElementsByClassName',
    'includes', 'indexOf', 'split', 'join', 'replace', 'trim'
}

IGNORE_READS = {
    'console', 'window', 'document', 'Math', 'JSON',
    'undefined', 'null', 'true', 'false', 'e', 'event'
}

SIDE_EFFECT_ICONS = {
    "network": "🌐", "execution": "⚡", "dom": "💉",
    "storage": "🗄️", "sensitive": "📋", "dynamic": "🔗"
}

INLINE_HANDLER_RE = re.compile(r'^on[a-z]+$')


def classify_functions(functions):
    main_funcs = {}
    ui_funcs = {}
    for name, func in functions.items():
        is_anonymous = name.startswith("anonymous@")
        has_effects = len(func.side_effects) > 0
        has_custom_calls = len(func.calls) > 0
        has_activity = len(func.builtins) > 0 or len(func.reads) > 0 or len(func.writes) > 0
        if is_anonymous and not has_effects and not has_custom_calls:
            if has_activity:
                ui_funcs[name] = func
        else:
            main_funcs[name] = func
    return main_funcs, ui_funcs


@dataclass
class FunctionInfo:
    name: str
    start_line: int
    end_line: int
    calls: Set[str] = field(default_factory=set)
    builtins: Set[str] = field(default_factory=set)
    side_effects: Set[str] = field(default_factory=set)
    reads: Set[str] = field(default_factory=set)
    writes: Set[str] = field(default_factory=set)


@dataclass
class ReportData:
    html_file: str
    warnings: List[str] = field(default_factory=list)
    functions: Dict[str, FunctionInfo] = field(default_factory=dict)
    ui_functions: Dict[str, FunctionInfo] = field(default_factory=dict)
    dependencies: List[Dependency] = field(default_factory=list)


class HTMLJSAnalyzer:
    def __init__(self, html_path: str):
        self.html_path = html_path
        self.parser = get_parser('javascript')
        self.report = ReportData(html_file=os.path.basename(html_path))
        self.script_blocks: List[tuple] = []

    def analyze(self) -> ReportData:
        self._parse_html()
        self._analyze_js()
        return self.report

    def _parse_html(self):
        with open(self.html_path, 'r', encoding='utf-8', errors='replace') as f:
            html_content = f.read()

        soup = BeautifulSoup(html_content, 'html.parser')

        resources = []
        for script in soup.find_all('script'):
            src = script.get('src')
            if src:
                resources.append((src, 'script'))
                src_display = src if src.startswith(('http://', 'https://', '//')) else f"(relative) {src}"
                self.report.warnings.append(f"外部 script 引用：{src_display}")
            elif script.string:
                start_line = getattr(script, 'sourceline', 1)
                self.script_blocks.append((start_line, script.string))

        for link in soup.find_all('link'):
            rel = link.get('rel') or []
            href = link.get('href')
            if href and any('stylesheet' in r.lower() for r in rel):
                resources.append((href, 'stylesheet'))

        self.report.dependencies = analyze_dependencies(resources)

        for iframe in soup.find_all('iframe'):
            self.report.warnings.append(f"發現 iframe 標籤 (src: {iframe.get('src')})")

        if soup.find('meta', attrs={'http-equiv': lambda x: x and x.lower() == 'refresh'}):
            self.report.warnings.append("發現 <meta http-equiv=\"refresh\"> (自動跳轉)")

        for tag in soup.find_all(True):
            for attr in tag.attrs:
                if INLINE_HANDLER_RE.match(attr):
                    self.report.warnings.append(f"發現 inline event handler: {attr} 於 <{tag.name}>")
                    break

    def _analyze_js(self):
        sys.setrecursionlimit(max(sys.getrecursionlimit(), 5000))
        for offset_line, js_code in self.script_blocks:
            tree = self.parser.parse(bytes(js_code, "utf8"))
            self._traverse_ast(tree.root_node, offset_line)

    def _traverse_ast(self, node: TSNode, offset_line: int, current_func: str = None):
        func_name = current_func

        if node.type in ('function_declaration', 'function_expression', 'arrow_function', 'method_definition'):
            name_node = None
            if node.type in ('function_declaration', 'method_definition'):
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

            if node.type == 'call_expression':
                callee = node.child_by_field_name('function')
                if callee:
                    callee_text = callee.text.decode('utf8')
                    callee_name = callee_text.split('.')[-1]
                    if callee_name in BUILTIN_METHODS:
                        func_info.builtins.add(callee_name)
                    else:
                        func_info.calls.add(callee_name)

            if node.type in ('identifier', 'property_identifier'):
                token = node.text.decode('utf8')
                category = SIDE_EFFECTS_REVERSE.get(token)
                if category:
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

            elif node.type == 'identifier' and node.parent and node.parent.type not in (
                'function_declaration', 'variable_declarator', 'property_identifier', 'member_expression'
            ):
                var_name = node.text.decode('utf8')
                if var_name not in IGNORE_READS:
                    func_info.reads.add(var_name)

        for child in node.children:
            self._traverse_ast(child, offset_line, func_name)

    def _extract_identifiers_as_reads(self, node: TSNode, func_info: FunctionInfo):
        if node.type == 'identifier':
            var_name = node.text.decode('utf8')
            if var_name not in IGNORE_READS:
                func_info.reads.add(var_name)
        for child in node.children:
            self._extract_identifiers_as_reads(child, func_info)


class Exporter:
    def __init__(self, report: ReportData):
        self.report = report
        self.icons = SIDE_EFFECT_ICONS
        self.main_funcs, self.ui_funcs = classify_functions(report.functions)

    def render_markdown(self) -> str:
        side_effect_funcs = [f for f in self.main_funcs.values() if f.side_effects]

        lines = [
            f"# 分析報告：{self.report.html_file}",
            "\n## 整體摘要 (主邏輯)",
            f"- 函式總數：{len(self.main_funcs)}",
            f"- 含副作用函式：**{len(side_effect_funcs)}**",
            f"- UI/常規輔助函式：{len(self.ui_funcs)} (見獨立頁籤)",
        ]

        if self.report.warnings:
            lines.append("\n## 整檔警告")
            for w in self.report.warnings:
                lines.append(f"- ⚠️ **{w}**")

        lines.append("\n## 主函式清單")
        self._append_function_details(lines, self.main_funcs)
        return "\n".join(lines)

    def render_ui_markdown(self) -> str:
        lines_ui = ["# 常規腳本 (UI/狀態操作)\n"]
        if not self.ui_funcs:
            lines_ui.append("*未偵測到純常規 UI 腳本。*")
        else:
            lines_ui.append("> 此區塊列出僅包含內建方法 (如 `forEach`, `addEventListener`, `classList.add`)，且無危險副作用的匿名函式。\n")
            self._append_function_details(lines_ui, self.ui_funcs)
        return "\n".join(lines_ui)

    def render_mermaid(self) -> tuple[str, bool]:
        return generate_mermaid_flowchart(self.main_funcs)

    def render_sbom_markdown(self) -> str:
        meta = get_db_metadata()
        src_line = f"> 漏洞資料來源：{meta['source']}"
        if meta["updated_at"]:
            src_line += f"｜更新時間：{meta['updated_at']}"

        deps = self.report.dependencies
        if not deps:
            return ("# 相依套件 SBOM\n\n" + src_line +
                    "\n\n*未偵測到外部相依套件（檔案僅含內嵌程式碼）。*")

        vuln_count = sum(1 for d in deps if d.vulnerabilities)
        lines = [
            "# 相依套件 SBOM",
            "\n" + src_line,
            "> 涵蓋常見前端函式庫的已知 CVE，非完整掃描。\n",
            f"- 外部相依套件：{len(deps)}",
            f"- 含已知漏洞套件：**{vuln_count}**",
            "\n## 套件清單",
        ]
        for dep in deps:
            version = dep.version if dep.version else "未知"
            if dep.vulnerabilities:
                lines.append(f"\n### 🚨 <mark>{dep.name} `{version}` (含已知漏洞)</mark>")
            else:
                lines.append(f"\n### {dep.name} `{version}`")
            lines.append(f"- 來源：{dep.source}")
            lines.append(f"- 類型：{dep.kind}")
            if dep.vulnerabilities:
                lines.append("- 已知漏洞：")
                for v in dep.vulnerabilities:
                    icon = SEVERITY_ICONS.get(v["severity"], "")
                    lines.append(
                        f"  - {icon} **{v['id']}** ({v['severity']}) — "
                        f"{v['desc']}，修復版本：{v['fixed']}"
                    )
            else:
                lines.append("- 已知漏洞：無比對到")
        return "\n".join(lines)

    def _append_function_details(self, lines: List[str], func_dict: Dict[str, FunctionInfo]):
        for func in func_dict.values():
            icon_str = "".join([self.icons.get(se, "") for se in sorted(func.side_effects)])

            if func.side_effects:
                lines.append(f"\n### 🚨 <mark>{icon_str} {func.name} (含風險)</mark>")
            else:
                lines.append(f"\n### {func.name}")

            lines.append(f"- 位置：第 {func.start_line}-{func.end_line} 行")

            calls = ", ".join(sorted(func.calls)) if func.calls else "無"
            builtins = ", ".join(sorted(func.builtins)) if func.builtins else "無"
            lines.append(f"- 呼叫函式：{calls}")
            lines.append(f"- 內建方法：{builtins}")

            reads = ", ".join(sorted(func.reads)) if func.reads else "無"
            writes = ", ".join(sorted(func.writes)) if func.writes else "無"
            lines.append(f"- 讀取變數：{reads}")
            lines.append(f"- 寫入變數：{writes}")

            if func.side_effects:
                effects = ", ".join(sorted(func.side_effects))
                lines.append(f"- **副作用：{effects}** ⚠️")
            else:
                lines.append(f"- 副作用：無")

            callers = [f.name for f in self.main_funcs.values() if func.name in f.calls]
            caller_str = ", ".join(callers) if callers else "無"
            lines.append(f"- 被誰呼叫：{caller_str}")
