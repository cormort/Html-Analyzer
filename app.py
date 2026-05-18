import gradio as gr
import tempfile
import os
import shutil
from analyzer import HTMLJSAnalyzer, Exporter

# 引入我們剛剛寫好的 HTML 產生器
from export_html import generate_html_report

def analyze_uploaded_html(file_obj):
    if file_obj is None:
        return "⚠️ 請先上傳 HTML 檔案", "", gr.DownloadButton(visible=False)

    html_path = file_obj.name
    
    # 注意：這裡改用 tempfile.mkdtemp() 而不是 with 語句
    # 這是為了確保函式執行完畢後，資料夾與檔案依然存在，讓使用者可以點擊下載
    # (Gradio 本身的機制會定期清理這些被元件綁定的暫存檔，所以不用擔心伺服器塞爆)
    temp_dir = tempfile.mkdtemp()
    base_name = "output"
    
    try:
        # 1. 產生原本的 Markdown 和 Mermaid
        analyzer = HTMLJSAnalyzer(html_path)
        report_data = analyzer.analyze()
        
        exporter = Exporter(report_data, temp_dir, base_name)
        exporter.write_markdown()
        exporter.write_mermaid()
        
        md_path = os.path.join(temp_dir, f"{base_name}.report.md")
        mmd_path = os.path.join(temp_dir, f"{base_name}.flow.mmd")
        
        with open(md_path, "r", encoding="utf-8") as f:
            md_content = f.read()
            
        with open(mmd_path, "r", encoding="utf-8") as f:
            mmd_content = f.read()
            
        mermaid_markdown = f"""```mermaid
{mmd_content}
```"""
        
        # 2. 呼叫 export_html 產生獨立的 HTML 報告
        raw_html_report_path = generate_html_report(html_path, temp_dir)
        
        # 為了讓使用者下載時有一個易讀的檔名，我們重新命名它
        original_basename = os.path.splitext(os.path.basename(html_path))[0]
        download_friendly_path = os.path.join(temp_dir, f"{original_basename}_分析報告.html")
        shutil.move(raw_html_report_path, download_friendly_path)

        # 3. 返回給 Gradio：Markdown、Mermaid、顯示下載按鈕並綁定檔案路徑
        return md_content, mermaid_markdown, gr.DownloadButton(value=download_friendly_path, visible=True)
        
    except Exception as e:
        # 發生錯誤時，隱藏下載按鈕
        return f"❌ 分析失敗：{str(e)}", "", gr.DownloadButton(visible=False)

# 建立 Gradio 網頁介面
with gr.Blocks(title="HTML/JS 安全與結構分析工具") as demo:
    gr.Markdown("# 🔍 HTML/JS 程式碼分析工具")
    gr.Markdown("上傳 LLM 產生的 HTML 檔案，自動分析內嵌 JavaScript 的函式結構與潛在風險副作用。")
    
    with gr.Row():
        with gr.Column(scale=1):
            file_input = gr.File(label="上傳單檔 .html", file_types=[".html"])
            analyze_btn = gr.Button("開始分析", variant="primary")
            
            # 新增匯出按鈕：初始狀態設為隱藏 (visible=False)
            download_btn = gr.DownloadButton("📥 匯出獨立 HTML 報告", visible=False)
            
        with gr.Column(scale=2):
            with gr.Tabs():
                with gr.Tab("文字報告"):
                    md_output = gr.Markdown(label="Markdown 報告")
                with gr.Tab("流程圖 (Mermaid)"):
                    mmd_output = gr.Markdown(label="呼叫關係圖")

    # 將 download_btn 加入 outputs，讓函式可以動態控制它
    analyze_btn.click(
        fn=analyze_uploaded_html, 
        inputs=file_input, 
        outputs=[md_output, mmd_output, download_btn]
    )

if __name__ == "__main__":
    # 關閉實驗性的 ssr_mode，把渲染權交回給瀏覽器，Mermaid 就能正常工作了！
    demo.launch(ssr_mode=False)