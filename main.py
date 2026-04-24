import argparse
import os
from dotenv import load_dotenv
from src.parser import IntelParser
from src.renderer import MarkdownRenderer
from src.utils import get_report_content

load_dotenv()

def main():
    parser = argparse.ArgumentParser(description="T2DE: Threat-to-Detection Engine")
    parser.add_argument("--input", required=True, help="Path to input text file or URL to threat report")
    parser.add_argument("--output", default="output.md", help="Path to save Markdown")
    
    args = parser.parse_args()

    if not os.getenv("ANTHROPIC_API_KEY"):
        print("[-] Error: ANTHROPIC_API_KEY not found in .env")
        return

    try:
        # Get content from either file or URL
        report_content = get_report_content(args.input)
    except FileNotFoundError as e:
        print(f"[-] Error: {e}")
        return
    except Exception as e:
        print(f"[-] Error fetching content: {e}")
        return

    print("[*] Parsing threat report with AI...")
    t2de = IntelParser()
    structured_data = t2de.parse_report(report_content)
    
    print("[*] Generating markdown output...")
    final_md = MarkdownRenderer.to_markdown(structured_data)
    
    with open(args.output, "w", encoding="utf-8") as f:
        f.write(final_md)
    print(f"[+] Success! Analysis saved to {args.output}")

if __name__ == "__main__":
    main()