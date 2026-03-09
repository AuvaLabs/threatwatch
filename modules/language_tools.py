import logging
from langdetect import detect


def detect_language(text):
    try:
        return detect(text)
    except Exception as e:
        logging.warning(f"Language detection failed for: {text} - {e}")
        return "en"
