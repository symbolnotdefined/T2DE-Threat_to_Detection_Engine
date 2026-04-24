import os
import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse

def is_url(input_string: str) -> bool:
    """
    Check if the input string is a valid URL.
    
    Args:
        input_string: The string to check
        
    Returns:
        True if the string is a URL, False otherwise
    """
    try:
        result = urlparse(input_string)
        return all([result.scheme, result.netloc]) and result.scheme in ['http', 'https']
    except Exception:
        return False

def fetch_url_content(url: str) -> str:
    """
    Fetch content from a URL and extract text.
    
    Args:
        url: The URL to fetch content from
        
    Returns:
        The extracted text content from the URL
        
    Raises:
        requests.RequestException: If there's an error fetching the URL
    """
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
    }
    
    response = requests.get(url, headers=headers, timeout=30)
    response.raise_for_status()
    
    # Try to extract text content from HTML
    content_type = response.headers.get('Content-Type', '').lower()
    
    if 'text/html' in content_type:
        soup = BeautifulSoup(response.content, 'html.parser')
        
        # Remove script and style elements
        for script in soup(['script', 'style', 'nav', 'footer', 'header']):
            script.decompose()
        
        # Get text
        text = soup.get_text(separator='\n', strip=True)
        
        # Clean up whitespace
        lines = (line.strip() for line in text.splitlines())
        chunks = (phrase.strip() for line in lines for phrase in line.split("  "))
        text = '\n'.join(chunk for chunk in chunks if chunk)
        
        return text
    else:
        # For plain text or other content types, return as-is
        return response.text

def get_report_content(input_path: str) -> str:
    """
    Get report content from either a file path or URL.
    
    Args:
        input_path: Either a file path or URL
        
    Returns:
        The content of the report
        
    Raises:
        FileNotFoundError: If the file doesn't exist
        requests.RequestException: If there's an error fetching the URL
    """
    if is_url(input_path):
        print(f"[*] Fetching content from URL: {input_path}")
        return fetch_url_content(input_path)
    else:
        print(f"[*] Reading content from file: {input_path}")
        if not os.path.exists(input_path):
            raise FileNotFoundError(f"File not found: {input_path}")
        
        with open(input_path, "r", encoding="utf-8") as f:
            return f.read()

# Made with Bob
