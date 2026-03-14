import logging
from lingua import LanguageDetectorBuilder

_detector = LanguageDetectorBuilder.from_all_languages().build()


def detect_language(text):
    try:
        result = _detector.detect_language_of(text)
        return result.iso_code_639_1.name.lower() if result else "en"
    except Exception as e:
        logging.warning(f"Language detection failed: {e}")
        return "en"
