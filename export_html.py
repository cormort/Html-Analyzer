import os
import sys
import argparse
import re
from analyzer import HTMLJSAnalyzer

def sanitize_id(name):
    return re.sub(r'[^a-zA-Z0-9]', '_', name)

def sanitize_label(name):
    return name.replace('<', '&lt;').replace('>', '&gt;')

def generate_html_report(html_path, output_dir=None):
    # 執行分析
    analyzer = HTMLJSAnalyzer(html_path)
    report = analyzer.analyze()
    
    # 決定輸出路徑
    base_name = os.path.splitext(os.path.basename(html_path))[0]
    if not output_dir:
        output_dir = os.path.dirname(os.path.abspath(html_path))
    output_path = os.path.join(output_dir, f"{base_name}_report.html")

    # 1. 產生 Mermaid 字串
    mermaid_lines = ["flowchart TD"]
    for func in report.functions.values():
        safe_id = sanitize_id(func.name)
        safe_label = sanitize_label(func.name)
        node_def = f'    {safe_id}["{safe_label}()"]'
        
        if func.side_effects:
            primary_class = list(func.side_effects)[0]
            node_def += f":::{primary_class}"
        mermaid_lines.append(node_def)
        
        for call in func.calls:
            if call in report.functions:
                safe_call_id = sanitize_id(call)
                mermaid_lines.append(f"    {safe_id} --> {safe_call_id}")

    mermaid_lines.extend([
        "",
        "    classDef network fill:#fee,stroke:#c00,stroke-width:3px,color:#000",
        "    classDef execution fill:#fee,stroke:#c00,stroke-width:3px,color:#000",
        "    classDef dom fill:#fef,stroke:#90c,stroke-width:3px,color:#000",
        "    classDef storage fill:#eef,stroke:#36c,stroke-width:3px,color:#000",
        "    classDef sensitive fill:#ffe,stroke:#c90,stroke-width:3px,color:#000",
        "    classDef dynamic fill:#efe,stroke:#090,stroke-width:3px,color:#000"
    ])
    mermaid_str = "\n".join(mermaid_lines)

    # 2. 準備統計資料與圖示
    side_effect_funcs = [f for f in report.functions.values() if f.side_effects]
    icons = {
        "network": "🌐", "execution": "⚡", "dom": "💉",
        "storage": "🗄️", "sensitive": "📋", "dynamic": "🔗"
    }

    # 3. 組合 HTML 結構 (加入 Tab 樣式與邏輯)
    html_content = f"""<!DOCTYPE html>
<html lang="zh-TW">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>分析報告: {report.html_file}</title>
    <style>
        :root {{
            --bg-color: #f8f9fa;
            --text-color: #333;
            --card-bg: #fff;
            --border-color: #dee2e6;
            --danger-bg: #fff5f5;
            --danger-border: #ffc9c9;
            --danger-text: #e03131;
            --primary-color: #f97316; /* 呼應 Gradio 的橘色系 */
        }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            background-color: var(--bg-color);
            color: var(--text-color);
            line-height: 1.6;
            padding: 20px;
            max-width: 1200px;
            margin: 0 auto;
        }}
        h1, h2, h3 {{ color: #212529; }}
        
        /* 頁籤導覽列樣式 */
        .tab-nav {{
            display: flex;
            border-bottom: 2px solid var(--border-color);
            margin-bottom: 20px;
        }}
        .tab-btn {{
            background: none;
            border: none;
            padding: 12px 24px;
            font-size: 16px;
            cursor: pointer;
            color: #6c757d;
            border-bottom: 3px solid transparent;
            margin-bottom: -2px;
            transition: all 0.2s ease;
        }}
        .tab-btn:hover {{ color: #495057; }}
        .tab-btn.active {{
            color: var(--primary-color);
            border-bottom-color: var(--primary-color);
            font-weight: bold;
        }}
        
        /* 頁籤內容區塊 */
        .tab-content {{ display: none; animation: fadeIn 0.3s; }}
        .tab-content.active {{ display: block; }}
        @keyframes fadeIn {{ from {{ opacity: 0; }} to {{ opacity: 1; }} }}

        /* 統計與卡片樣式 */
        .header-panel {{
            background: var(--card-bg);
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.05);
            margin-bottom: 20px;
        }}
        .summary-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-top: 15px;
        }}
        .stat-box {{
            background: #e9ecef;
            padding: 15px;
            border-radius: 6px;
            text-align: center;
        }}
        .stat-box .number {{ font-size: 24px; font-weight: bold; color: #495057; }}
        .stat-box.danger {{ background: var(--danger-bg); border: 1px solid var(--danger-border); }}
        .stat-box.danger .number {{ color: var(--danger-text); }}
        
        .mermaid-container {{
            background: var(--card-bg);
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.05);
            overflow-x: auto;
            text-align: center;
        }}
        
        .func-list {{ display: grid; gap: 15px; }}
        .func-card {{
            background: var(--card-bg);
            border: 1px solid var(--border-color);
            border-left: 5px solid #ced4da;
            padding: 15px;
            border-radius: 6px;
        }}
        .func-card.has-risk {{
            border-left-color: var(--danger-text);
            background-color: var(--danger-bg);
        }}
        .func-name {{ font-size: 1.2em; font-weight: bold; margin-bottom: 10px; display: flex; align-items: center; gap: 8px; }}
        .func-meta {{ font-size: 0.9em; color: #6c757d; margin-bottom: 10px; }}
        .tag {{
            display: inline-block;
            padding: 2px 8px;
            border-radius: 12px;
            font-size: 0.85em;
            background: #e9ecef;
            color: #495057;
            margin-right: 5px;
        }}
        .tag.risk-tag {{ background: #ffe3e3; color: var(--danger-text); font-weight: bold; border: 1px solid var(--danger-border); }}
        
        .warnings-list {{ color: var(--danger-text); font-weight: bold; }}
    </style>
</head>
<body>

    <h1>🔍 分析報告：{report.html_file}</h1>

    <div class="tab-nav">
        <button class="tab-btn active" onclick="switchTab('tab-report', this)">文字報告</button>
        <button class="tab-btn" onclick="switchTab('tab-flowchart', this)">流程圖 (Mermaid)</button>
    </div>

    <div id="tab-report" class="tab-content active">
        <div class="header-panel">
            <div class="summary-grid">
                <div class="stat-box">
                    <div>函式總數</div>
                    <div class="number">{len(report.functions)}</div>
                </div>
                <div class="stat-box {'danger' if side_effect_funcs else ''}">
                    <div>含副作用函式</div>
                    <div class="number">{len(side_effect_funcs)}</div>
                </div>
                <div class="stat-box {'danger' if report.warnings else ''}">
                    <div>整檔警告</div>
                    <div class="number">{len(report.warnings)}</div>
                </div>
            </div>

            {f'''
            <div style="margin-top: 20px;">
                <h3>⚠️ 整檔警告</h3>
                <ul class="warnings-list">
                    {"".join(f"<li>{w}</li>" for w in report.warnings)}
                </ul>
            </div>
            ''' if report.warnings else ''}
        </div>

        <h2>函式詳細清單</h2>
        <div class="func-list">
"""
    
    # 組合函式清單 HTML
    for func in report.functions.values():
        is_risk = len(func.side_effects) > 0
        card_class = "func-card has-risk" if is_risk else "func-card"
        icon_str = "".join([icons.get(se, "") for se in func.side_effects])
        
        calls = ", ".join(func.calls) if func.calls else "無"
        callers = [f.name for f in report.functions.values() if func.name in f.calls]
        caller_str = ", ".join(callers) if callers else "無"
        
        html_content += f'''
            <div class="{card_class}">
                <div class="func-name">
                    {icon_str} {func.name}()
                    { '<span class="tag risk-tag">含風險</span>' if is_risk else ''}
                </div>
                <div class="func-meta">位置：第 {func.start_line} - {func.end_line} 行</div>
                <div><strong>呼叫其他函式：</strong> {calls}</div>
                <div><strong>被誰呼叫：</strong> {caller_str}</div>
                <div style="margin-top: 8px;">
                    <strong>副作用：</strong> 
                    { "".join(f'<span class="tag risk-tag">{se}</span>' for se in func.side_effects) if func.side_effects else '<span class="tag">無</span>' }
                </div>
            </div>
        '''

    html_content += f"""
        </div>
    </div>

    <div id="tab-flowchart" class="tab-content">
        <div class="mermaid-container">
            <pre class="mermaid">
{mermaid_str}
            </pre>
        </div>
    </div>

    <footer style="margin-top: 40px; text-align: center; color: #adb5bd; font-size: 0.9em;">
        免責聲明：此工具僅為輔助審查用途，基於靜態分析，無法保證偵測所有動態行為或繞過手法。
    </footer>

    <script>
        function switchTab(tabId, btnElement) {{
            // 隱藏所有內容區塊
            document.querySelectorAll('.tab-content').forEach(el => el.classList.remove('active'));
            // 移除所有按鈕的 active 狀態
            document.querySelectorAll('.tab-btn').forEach(el => el.classList.remove('active'));
            
            // 顯示被點擊的區塊，並將按鈕設為 active
            document.getElementById(tabId).classList.add('active');
            btnElement.classList.add('active');
        }}
    </script>

    <script type="module">
        import mermaid from 'https://cdn.jsdelivr.net/npm/mermaid@10/dist/mermaid.esm.min.mjs';
        mermaid.initialize({{ startOnLoad: true, theme: 'base' }});
    </script>
</body>
</html>
"""

    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(html_content)
    
    return output_path

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="產生 HTML 格式的靜態分析報告")
    parser.add_argument("input", help="要分析的 HTML 檔案路徑")
    parser.add_argument("--output-dir", help="輸出資料夾 (預設與輸入檔同目錄)")
    
    args = parser.parse_args()
    
    if not os.path.exists(args.input):
        print(f"錯誤：找不到檔案 {args.input}", file=sys.stderr)
        sys.exit(1)
        
    print(f"開始分析 {args.input} 並產生 HTML 報告...")
    try:
        out_file = generate_html_report(args.input, args.output_dir)
        print(f"✅ 成功！報告已匯出至：{out_file}")
    except Exception as e:
        print(f"❌ 發生錯誤：{e}", file=sys.stderr)
        sys.exit(1)
