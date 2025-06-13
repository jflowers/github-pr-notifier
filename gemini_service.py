# gemini_service.py
import os
import google.generativeai as genai
from dotenv import load_dotenv

load_dotenv()

try:
    genai.configure(api_key=os.environ["GEMINI_API_KEY"])
    model = genai.GenerativeModel('gemini-pro')
except Exception as e:
    print(f"Error configuring Gemini: {e}")
    model = None

def summarize_pr(title: str, body: str) -> str:
    """Summarizes PR content using the Gemini API."""
    if not model:
        print("Gemini model not initialized. Returning raw content.")
        return "Could not generate summary."

    if not body:
        body = "No description provided."

    prompt = f"""
    Please provide a concise, one-sentence summary of the following GitHub Pull Request.
    Focus on the "what" and "why" of the change.

    Title: {title}
    Description:
    ---
    {body}
    ---

    Summary:
    """

    try:
        response = model.generate_content(prompt)
        # Clean up the response text
        summary = response.text.strip().replace('\n', ' ')
        return summary
    except Exception as e:
        print(f"Error calling Gemini API: {e}")
        return "Could not generate summary."