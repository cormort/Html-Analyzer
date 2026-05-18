import gradio as gr
import tempfile
import os
import shutil
import traceback
import logging
from analyzer import HTMLJSAnalyzer, Exporter
from export_html import generate_html_report

logging.basicConfig(level=logging.ERROR)

def analyze_uploaded_html(file_obj):
    if file_obj is None:
        return "⚠️ 請先上傳 HTML 檔案", "", "", gr.DownloadButton(visible=False)

    html_path = file_obj.name
    if not os.path.isfile(html_path):
        return "❌ 檔案不存在或路徑無效", "", "", gr.DownloadButton(visible=False)

    temp_dir = tempfile.mkdtemp()
    try:
        analyzer = HTMLJSAnalyzer(html_path)
        report_data = analyzer.analyze()

        exporter = Exporter(report_data)
        md_content = exporter.render_markdown()
        ui_content = exporter.render_ui_markdown()
        mmd_content, has_edges = exporter.render_mermaid()
        if not exporter.main_funcs:
            mermaid_markdown = "*無主函式呼叫關係可顯示。*"
        elif not has_edges:
            mermaid_markdown = f"```mermaid\n{mmd_content}\n```\n\n> 所有函式皆獨立運作，無互相呼叫或共享變數關係。"
        else:
            mermaid_markdown = f"```mermaid\n{mmd_content}\n```"

        raw_html_report_path = generate_html_report(html_path, temp_dir, report=report_data)
        original_basename = os.path.splitext(os.path.basename(html_path))[0]
        download_friendly_path = os.path.join(temp_dir, f"{original_basename}_分析報告.html")
        shutil.move(raw_html_report_path, download_friendly_path)

        return md_content, ui_content, mermaid_markdown, gr.DownloadButton(value=download_friendly_path, visible=True)

    except Exception as e:
        logging.error("Analysis failed: %s", traceback.format_exc())
        return f"❌ 分析失敗：{str(e)}", "", "", gr.DownloadButton(visible=False)

with gr.Blocks(title="HTML/JS 安全與結構分析工具") as demo:
    gr.Markdown("# 🔍 HTML/JS 程式碼分析工具")
    gr.Markdown("上傳 LLM 產生的 HTML 檔案，自動分析內嵌 JavaScript 的函式結構與潛在風險副作用。")

    with gr.Row():
        with gr.Column(scale=1):
            file_input = gr.File(label="上傳單檔 .html", file_types=[".html"])
            analyze_btn = gr.Button("開始分析", variant="primary")
            download_btn = gr.DownloadButton("📥 匯出獨立 HTML 報告", visible=False)

        with gr.Column(scale=2):
            with gr.Tabs():
                with gr.Tab("文字報告 (主邏輯)"):
                    md_output = gr.Markdown(label="主邏輯報告")
                with gr.Tab("常規腳本 (UI/狀態)"):
                    ui_output = gr.Markdown(label="常規腳本")
                with gr.Tab("流程圖 (Mermaid)"):
                    mmd_output = gr.Markdown(label="呼叫關係圖")

    analyze_btn.click(
        fn=analyze_uploaded_html,
        inputs=file_input,
        outputs=[md_output, ui_output, mmd_output, download_btn]
    )

if __name__ == "__main__":
    demo.launch(ssr_mode=False)
