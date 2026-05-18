import os
from html import escape as html_escape
from analyzer import HTMLJSAnalyzer, classify_functions, SIDE_EFFECT_ICONS
from mermaid_gen import generate_mermaid_flowchart
from sbom import SEVERITY_ICONS


def _build_caller_index(func_dict):
    index = {}
    for f in func_dict.values():
        for call in f.calls:
            if call not in index:
                index[call] = []
            index[call].append(f.name)
    return index


def _generate_func_cards_html(func_dict, icons, caller_index):
    html = '<div class="func-list">'
    for func in func_dict.values():
        is_risk = len(func.side_effects) > 0
        card_class = "func-card has-risk" if is_risk else "func-card"
        icon_str = "".join([icons.get(se, "") for se in sorted(func.side_effects)])

        safe_name = html_escape(func.name)
        calls = ", ".join(html_escape(c) for c in sorted(func.calls)) if func.calls else "無"
        builtins = ", ".join(html_escape(b) for b in sorted(func.builtins)) if func.builtins else "無"
        callers = caller_index.get(func.name, [])
        caller_str = ", ".join(html_escape(c) for c in callers) if callers else "無"

        html += f'''
            <div class="{card_class}">
                <div class="func-name">
                    {icon_str} {safe_name}()
                    { '<span class="tag risk-tag">含風險</span>' if is_risk else ''}
                </div>
                <div class="func-meta">位置：第 {func.start_line} - {func.end_line} 行</div>
                <div><strong>呼叫函式：</strong> {calls}</div>
                <div><strong>內建方法：</strong> {builtins}</div>
                <div><strong>被誰呼叫：</strong> {caller_str}</div>
                <div style="margin-top: 8px;">
                    <strong>副作用：</strong>
                    { "".join(f'<span class="tag risk-tag">{html_escape(se)}</span>' for se in sorted(func.side_effects)) if func.side_effects else '<span class="tag">無</span>' }
                </div>
            </div>
        '''
    html += '</div>'
    return html


def _generate_sbom_html(dependencies):
    if not dependencies:
        return "<p><em>未偵測到外部相依套件（檔案僅含內嵌程式碼）。</em></p>"

    html = '<div class="func-list">'
    for dep in dependencies:
        is_risk = len(dep.vulnerabilities) > 0
        card_class = "func-card has-risk" if is_risk else "func-card"
        name = html_escape(dep.name)
        version = html_escape(dep.version) if dep.version else "未知"
        source = html_escape(dep.source)
        risk_badge = '<span class="tag risk-tag">含已知漏洞</span>' if is_risk else ''

        if dep.vulnerabilities:
            vuln_html = ""
            for v in dep.vulnerabilities:
                icon = SEVERITY_ICONS.get(v["severity"], "")
                vuln_html += (
                    f'<div class="warnings-list">{icon} {html_escape(v["id"])} '
                    f'({html_escape(v["severity"])}) — {html_escape(v["desc"])}'
                    f'，修復版本：{html_escape(v["fixed"])}</div>'
                )
        else:
            vuln_html = '<span class="tag">無比對到</span>'

        html += f'''
            <div class="{card_class}">
                <div class="func-name">{name} <code>{version}</code> {risk_badge}</div>
                <div class="func-meta">類型：{html_escape(dep.kind)}</div>
                <div style="word-break: break-all;"><strong>來源：</strong> {source}</div>
                <div style="margin-top: 8px;"><strong>已知漏洞：</strong> {vuln_html}</div>
            </div>
        '''
    html += '</div>'
    return html


def generate_html_report(html_path, output_dir=None, report=None):
    if report is None:
        analyzer = HTMLJSAnalyzer(html_path)
        report = analyzer.analyze()

    main_funcs, ui_funcs = classify_functions(report.functions)

    base_name = os.path.splitext(os.path.basename(html_path))[0]
    if not output_dir:
        output_dir = os.path.dirname(os.path.abspath(html_path))
    output_path = os.path.join(output_dir, f"{base_name}_report.html")

    mermaid_str, has_edges = generate_mermaid_flowchart(main_funcs)

    icons = SIDE_EFFECT_ICONS
    main_caller_index = _build_caller_index(main_funcs)
    ui_caller_index = _build_caller_index(ui_funcs)

    safe_html_file = html_escape(report.html_file)

    main_cards_html = _generate_func_cards_html(main_funcs, icons, main_caller_index) if main_funcs else "<p><em>未偵測到主函式。所有函式皆歸類為常規腳本 (見「常規腳本」頁籤)。</em></p>"
    ui_cards_html = _generate_func_cards_html(ui_funcs, icons, ui_caller_index) if ui_funcs else "<p><em>未偵測到純常規 UI 腳本。</em></p>"
    no_edges_hint = '<p style="color: #6c757d; margin-top: 12px;"><em>所有函式皆獨立運作，無互相呼叫或共享變數關係。</em></p>' if main_funcs and not has_edges else ''
    if main_funcs:
        flowchart_html = f'<pre id="mermaid-graph" style="display: none;">\n{mermaid_str}\n</pre><div id="mermaid-output"></div>{no_edges_hint}'
    else:
        flowchart_html = '<p><em>無主函式呼叫關係可顯示。</em></p>'

    has_side_effects = any(f.side_effects for f in main_funcs.values())
    side_effect_count = sum(1 for f in main_funcs.values() if f.side_effects)

    sbom_html = _generate_sbom_html(report.dependencies)
    vuln_dep_count = sum(1 for d in report.dependencies if d.vulnerabilities)

    html_content = f"""<!DOCTYPE html>
<html lang="zh-TW">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>分析報告: {safe_html_file}</title>
    <style>
        :root {{
            --bg-color: #f8f9fa; --text-color: #333; --card-bg: #fff;
            --border-color: #dee2e6; --danger-bg: #fff5f5; --danger-border: #ffc9c9;
            --danger-text: #e03131; --primary-color: #f97316;
        }}
        body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background-color: var(--bg-color); color: var(--text-color); line-height: 1.6; padding: 20px; max-width: 1200px; margin: 0 auto; }}
        h1, h2, h3 {{ color: #212529; }}
        .tab-nav {{ display: flex; border-bottom: 2px solid var(--border-color); margin-bottom: 20px; }}
        .tab-btn {{ background: none; border: none; padding: 12px 24px; font-size: 16px; cursor: pointer; color: #6c757d; border-bottom: 3px solid transparent; margin-bottom: -2px; transition: all 0.2s ease; }}
        .tab-btn:hover {{ color: #495057; }}
        .tab-btn.active {{ color: var(--primary-color); border-bottom-color: var(--primary-color); font-weight: bold; }}
        .tab-container {{ position: relative; width: 100%; }}
        .tab-content {{ display: none; }}
        .tab-content.active {{ display: block; animation: fadeIn 0.3s; }}
        #tab-flowchart.tab-content {{ display: block; position: absolute; left: -9999px; top: -9999px; visibility: hidden; width: 100%; }}
        #tab-flowchart.tab-content.active {{ position: relative; left: 0; top: 0; visibility: visible; }}
        @keyframes fadeIn {{ from {{ opacity: 0; }} to {{ opacity: 1; }} }}
        .header-panel {{ background: var(--card-bg); padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.05); margin-bottom: 20px; }}
        .summary-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin-top: 15px; }}
        .stat-box {{ background: #e9ecef; padding: 15px; border-radius: 6px; text-align: center; }}
        .stat-box .number {{ font-size: 24px; font-weight: bold; color: #495057; }}
        .stat-box.danger {{ background: var(--danger-bg); border: 1px solid var(--danger-border); }}
        .stat-box.danger .number {{ color: var(--danger-text); }}
        .mermaid-container {{ background: var(--card-bg); padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.05); overflow-x: auto; text-align: center; }}
        .func-list {{ display: grid; gap: 15px; }}
        .func-card {{ background: var(--card-bg); border: 1px solid var(--border-color); border-left: 5px solid #ced4da; padding: 15px; border-radius: 6px; }}
        .func-card.has-risk {{ border-left-color: var(--danger-text); background-color: var(--danger-bg); }}
        .func-name {{ font-size: 1.2em; font-weight: bold; margin-bottom: 10px; display: flex; align-items: center; gap: 8px; }}
        .func-meta {{ font-size: 0.9em; color: #6c757d; margin-bottom: 10px; }}
        .tag {{ display: inline-block; padding: 2px 8px; border-radius: 12px; font-size: 0.85em; background: #e9ecef; color: #495057; margin-right: 5px; }}
        .tag.risk-tag {{ background: #ffe3e3; color: var(--danger-text); font-weight: bold; border: 1px solid var(--danger-border); }}
        .warnings-list {{ color: var(--danger-text); font-weight: bold; }}
    </style>
</head>
<body>
    <h1>🔍 分析報告：{safe_html_file}</h1>

    <div class="tab-nav">
        <button class="tab-btn active" onclick="switchTab('tab-report', this)">主邏輯報告</button>
        <button class="tab-btn" onclick="switchTab('tab-ui-scripts', this)">常規腳本 (UI/狀態)</button>
        <button class="tab-btn" onclick="switchTab('tab-sbom', this)">相依套件 (SBOM)</button>
        <button class="tab-btn" onclick="switchTab('tab-flowchart', this)">流程圖 (Mermaid)</button>
    </div>

    <div class="tab-container">
        <div id="tab-report" class="tab-content active">
            <div class="header-panel">
                <div class="summary-grid">
                    <div class="stat-box">
                        <div>主函式總數</div>
                        <div class="number">{len(main_funcs)}</div>
                    </div>
                    <div class="stat-box {'danger' if has_side_effects else ''}">
                        <div>含副作用函式</div>
                        <div class="number">{side_effect_count}</div>
                    </div>
                    <div class="stat-box {'danger' if report.warnings else ''}">
                        <div>整檔警告</div>
                        <div class="number">{len(report.warnings)}</div>
                    </div>
                </div>
            </div>
            <h2>主函式詳細清單</h2>
            {main_cards_html}
        </div>

        <div id="tab-ui-scripts" class="tab-content">
            <h2>常規腳本 (UI/狀態操作)</h2>
            <p style="color: #6c757d;">此區塊列出僅包含內建方法 (如 <code>forEach</code>, <code>addEventListener</code>)，且無危險副作用的輔助函式。</p>
            {ui_cards_html}
        </div>

        <div id="tab-sbom" class="tab-content">
            <h2>相依套件 SBOM</h2>
            <p style="color: #6c757d;">外部相依套件清單與已知漏洞比對。漏洞資料為內建靜態清單，涵蓋常見前端函式庫的知名 CVE，非完整掃描。</p>
            <div class="header-panel">
                <div class="summary-grid">
                    <div class="stat-box">
                        <div>外部相依套件</div>
                        <div class="number">{len(report.dependencies)}</div>
                    </div>
                    <div class="stat-box {'danger' if vuln_dep_count else ''}">
                        <div>含已知漏洞套件</div>
                        <div class="number">{vuln_dep_count}</div>
                    </div>
                </div>
            </div>
            {sbom_html}
        </div>

        <div id="tab-flowchart" class="tab-content">
            <div class="mermaid-container">
                {flowchart_html}
            </div>
        </div>
    </div>

    <script>
        function switchTab(tabId, btnElement) {{
            document.querySelectorAll('.tab-content').forEach(el => el.classList.remove('active'));
            document.querySelectorAll('.tab-btn').forEach(el => el.classList.remove('active'));
            document.getElementById(tabId).classList.add('active');
            btnElement.classList.add('active');

            if (tabId === 'tab-flowchart' && window.renderMermaidGraph) {{
                setTimeout(window.renderMermaidGraph, 50);
            }}
        }}
    </script>
    <script type="module">
        import mermaid from 'https://cdn.jsdelivr.net/npm/mermaid@10/dist/mermaid.esm.min.mjs';
        mermaid.initialize({{ startOnLoad: false, theme: 'base' }});
        window.renderMermaidGraph = async function() {{
            const outputDiv = document.getElementById('mermaid-output');
            if (!outputDiv.hasAttribute('data-rendered')) {{
                const graphDef = document.getElementById('mermaid-graph').textContent;
                try {{
                    const {{ svg }} = await mermaid.render('mermaid-svg', graphDef);
                    outputDiv.innerHTML = svg;
                    outputDiv.setAttribute('data-rendered', 'true');
                }} catch (error) {{
                    outputDiv.innerHTML = '<div style="color:red">圖表渲染失敗: ' + error.message + '</div>';
                }}
            }}
        }};
    </script>
</body>
</html>
"""
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(html_content)
    return output_path
