# gemini_service.py
import os
import logging
import re
from typing import Optional

import google.generativeai as genai
from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger(__name__)

# Configuration
MAX_TITLE_LENGTH = 500
MAX_BODY_LENGTH = 5000
MAX_SUMMARY_LENGTH = 200

# Initialize Gemini model
model: Optional[genai.GenerativeModel] = None

try:
    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key:
        raise ValueError("GEMINI_API_KEY not found in environment variables")
    
    genai.configure(api_key=api_key)
    model = genai.GenerativeModel('gemini-pro')
    logger.info("Gemini model initialized successfully")
except Exception as e:
    logger.error(f"Error configuring Gemini: {e}")
    model = None

def sanitize_input(text: str) -> str:
    """Sanitize input text to prevent potential issues."""
    if not text:
        return ""
    
    # Remove potentially harmful patterns
    text = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]', '', text)
    # Normalize whitespace
    text = re.sub(r'\s+', ' ', text)
    return text.strip()

def validate_input(title: str, body: str) -> tuple[str, str]:
    """Validate and sanitize input parameters."""
    if not isinstance(title, str):
        title = str(title) if title else ""
    
    if not isinstance(body, str):
        body = str(body) if body else ""
    
    # Sanitize inputs
    title = sanitize_input(title)
    body = sanitize_input(body)
    
    # Truncate if too long
    if len(title) > MAX_TITLE_LENGTH:
        title = title[:MAX_TITLE_LENGTH] + "..."
        logger.warning(f"Title truncated to {MAX_TITLE_LENGTH} characters")
    
    if len(body) > MAX_BODY_LENGTH:
        body = body[:MAX_BODY_LENGTH] + "..."
        logger.warning(f"Body truncated to {MAX_BODY_LENGTH} characters")
    
    return title, body

def summarize_pr(title: str, body: str) -> str:
    """Summarizes PR content using the Gemini API."""
    if not model:
        logger.error("Gemini model not initialized. Cannot generate summary.")
        return "Summary unavailable - AI service not configured."
    
    try:
        # Validate and sanitize inputs
        title, body = validate_input(title, body)
        
        if not title:
            logger.warning("Empty title provided")
            return "Summary unavailable - no title provided."
        
        if not body:
            body = "No description provided."
        
        prompt = f"""
        Please provide a concise, one-sentence summary of the following GitHub Pull Request.
        Focus on the "what" and "why" of the change. Keep it under {MAX_SUMMARY_LENGTH} characters.
        
        Title: {title}
        Description:
        ---
        {body}
        ---
        
        Summary:
        """
        
        response = model.generate_content(prompt)
        
        if not response or not response.text:
            logger.warning("Empty response from Gemini API")
            return "Summary unavailable - empty response from AI service."
        
        # Clean up the response text
        summary = response.text.strip().replace('\n', ' ')
        
        # Truncate if too long
        if len(summary) > MAX_SUMMARY_LENGTH:
            summary = summary[:MAX_SUMMARY_LENGTH] + "..."
        
        logger.info("Successfully generated PR summary")
        return summary
        
    except Exception as e:
        logger.error(f"Error calling Gemini API: {str(e)}")
        return "Summary unavailable - AI service error."
