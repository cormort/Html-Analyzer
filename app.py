# app.py
import gradio as gr
import tempfile
import os
from analyzer import HTMLJSAnalyzer, Exporter

def analyze_uploaded_html(file_obj):
    if file_obj is None:
        return "⚠️ 請先上傳 HTML 檔案", ""

    # Gradio 會將上傳的檔案存為暫存檔，file_obj 裡面有路徑
    html_path = file_obj.name
    
    # 使用暫存資料夾來存放產出的報告，避免污染伺服器環境
    with tempfile.TemporaryDirectory() as temp_dir:
        base_name = "output"
        
        try:
            # 呼叫原本的核心邏輯 (完全不用改)
            analyzer = HTMLJSAnalyzer(html_path)
            report_data = analyzer.analyze()
            
            exporter = Exporter(report_data, temp_dir, base_name)
            exporter.write_markdown()
            exporter.write_mermaid()
            
            # 讀取產生的檔案內容
            md_path = os.path.join(temp_dir, f"{base_name}.report.md")
            mmd_path = os.path.join(temp_dir, f"{base_name}.flow.mmd")
            
            with open(md_path, "r", encoding="utf-8") as f:
                md_content = f.read()
                
            with open(mmd_path, "r", encoding="utf-8") as f:
                mmd_content = f.read()
                
            # Gradio 的 Markdown 支援 Mermaid 渲染，我們將其包裝起來
            mermaid_markdown = f"```mermaid\n{mmd_content}\n
```"
            
            return md_content, mermaid_markdown
            
        except Exception as e:
            return f"❌ 分析失敗：{str(e)}", ""

# 建立 Gradio 網頁介面
with gr.Blocks(title="HTML/JS 安全與結構分析工具") as demo:
    gr.Markdown("# 🔍 HTML/JS 程式碼分析工具")
    gr.Markdown("上傳 LLM 產生的 HTML 檔案，自動分析內嵌 JavaScript 的函式結構與潛在風險副作用。")
    
    with gr.Row():
        with gr.Column(scale=1):
            file_input = gr.File(label="上傳單檔 .html", file_types=[".html"])
            analyze_btn = gr.Button("開始分析", variant="primary")
            
        with gr.Column(scale=2):
            with gr.Tabs():
                with gr.Tab("文字報告"):
                    md_output = gr.Markdown(label="Markdown 報告")
                with gr.Tab("流程圖 (Mermaid)"):
                    mmd_output = gr.Markdown(label="呼叫關係圖")

    analyze_btn.click(
        fn=analyze_uploaded_html, 
        inputs=file_input, 
        outputs=[md_output, mmd_output]
    )

if __name__ == "__main__":
    demo.launch()
