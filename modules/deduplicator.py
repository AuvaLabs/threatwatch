import hashlib
import logging
import string
from pathlib import Path

from modules.config import (
    STATE_DIR,
    FUZZY_DEDUP_THRESHOLD,
    MAX_SEEN_TITLES,
    MAX_SEEN_HASHES,
)

SEEN_HASHES_FILE = STATE_DIR / "seen_hashes.txt"
SEEN_TITLES_FILE = STATE_DIR / "seen_titles.txt"

_STRIP_TABLE = str.maketrans("", "", string.punctuation)
_PREFIXES = ("breaking:", "update:", "exclusive:", "just in:", "alert:")

# Stop words filtered out for better word-shingle matching
_STOP_WORDS = frozenset({
    "a", "an", "the", "and", "or", "but", "in", "on", "at", "to", "for",
    "of", "with", "by", "from", "is", "are", "was", "were", "be", "been",
    "has", "have", "had", "that", "this", "it", "its", "as", "not", "no",
})


def normalize_title(title):
    text = title.lower().strip()
    for prefix in _PREFIXES:
        if text.startswith(prefix):
            text = text[len(prefix):].strip()
    text = text.translate(_STRIP_TABLE)
    return " ".join(text.split())


def _make_word_shingles(normalized):
    """Create word unigram + bigram shingles for robust fuzzy matching."""
    words = [w for w in normalized.split() if w not in _STOP_WORDS]
    if not words:
        return frozenset()
    shingles = set(words)  # unigrams
    for i in range(len(words) - 1):
        shingles.add(f"{words[i]} {words[i+1]}")  # bigrams
    return frozenset(shingles)


def _word_overlap_ratio(set_a, set_b):
    """Compute overlap ratio: |intersection| / min(|a|, |b|)."""
    if not set_a or not set_b:
        return 0.0
    intersection = len(set_a & set_b)
    smaller = min(len(set_a), len(set_b))
    return intersection / smaller if smaller > 0 else 0.0


class ShingleIndex:
    """Inverted index using word bigram shingles for fast fuzzy dedup."""

    def __init__(self):
        self._shingle_to_indices = {}
        self._title_shingles = []
        self._normalized_titles = []

    def add(self, normalized_title):
        idx = len(self._normalized_titles)
        shingles = _make_word_shingles(normalized_title)
        self._title_shingles.append(shingles)
        self._normalized_titles.append(normalized_title)
        for s in shingles:
            if s not in self._shingle_to_indices:
                self._shingle_to_indices[s] = []
            self._shingle_to_indices[s].append(idx)
        return idx

    def is_fuzzy_duplicate(self, normalized_title, threshold=FUZZY_DEDUP_THRESHOLD):
        shingles = _make_word_shingles(normalized_title)
        if not shingles:
            # Very short title — check exact match only
            return normalized_title in self._normalized_titles

        # Gather candidates: titles sharing at least one word bigram
        candidate_set = set()
        for s in shingles:
            for idx in self._shingle_to_indices.get(s, ()):
                candidate_set.add(idx)

        for idx in candidate_set:
            existing = self._normalized_titles[idx]
            if normalized_title == existing:
                return True
            similarity = _word_overlap_ratio(shingles, self._title_shingles[idx])
            if similarity >= threshold:
                logging.info(
                    f"Fuzzy duplicate ({similarity:.2f}): "
                    f"'{normalized_title}' ~ '{existing}'"
                )
                return True
        return False

    def find_best_match_index(self, normalized_title, start_idx,
                              threshold=FUZZY_DEDUP_THRESHOLD):
        shingles = _make_word_shingles(normalized_title)
        if not shingles:
            return -1

        candidate_set = set()
        for s in shingles:
            for idx in self._shingle_to_indices.get(s, ()):
                if idx >= start_idx:
                    candidate_set.add(idx)

        best_score = -1.0
        best_idx = -1
        for idx in candidate_set:
            existing = self._normalized_titles[idx]
            if normalized_title == existing:
                return idx - start_idx
            similarity = _word_overlap_ratio(shingles, self._title_shingles[idx])
            if similarity >= threshold and similarity > best_score:
                best_score = similarity
                best_idx = idx
        return best_idx - start_idx if best_idx >= 0 else -1

    def __len__(self):
        return len(self._normalized_titles)


def _load_lines(filepath):
    if not filepath.exists():
        return []
    with open(filepath, "r", encoding="utf-8") as f:
        return [line.strip() for line in f if line.strip()]


def _save_lines(filepath, lines, max_lines=None):
    filepath.parent.mkdir(parents=True, exist_ok=True)
    if max_lines and len(lines) > max_lines:
        lines = lines[-max_lines:]
    with open(filepath, "w", encoding="utf-8") as f:
        for line in lines:
            f.write(f"{line}\n")


def deduplicate_articles(articles):
    seen_hashes = set(_load_lines(SEEN_HASHES_FILE))
    seen_titles = _load_lines(SEEN_TITLES_FILE)

    # Build shingle index from previously seen titles
    index = ShingleIndex()
    for t in seen_titles:
        index.add(normalize_title(t))

    batch_start_idx = len(index)

    new_hashes = []
    new_titles = []
    unique_articles = []
    # Map hash -> index in unique_articles for cross-region merging
    hash_to_idx = {}

    for article in articles:
        raw_hash = article.get("hash")
        if not raw_hash:
            raw_hash = hashlib.sha256(
                (article["title"] + article["link"]).encode()
            ).hexdigest()
            article["hash"] = raw_hash

        if raw_hash in seen_hashes:
            # Merge region from duplicate into existing article in this batch
            if raw_hash in hash_to_idx:
                _merge_region(unique_articles[hash_to_idx[raw_hash]], article)
            logging.debug(f"Hash duplicate skipped: {article['link']}")
            continue

        normalized = normalize_title(article["title"])

        # Skip fuzzy dedup for dark web articles (structured titles with shared words)
        is_darkweb = article.get("darkweb", False)
        if not is_darkweb and index.is_fuzzy_duplicate(normalized):
            logging.info(f"Fuzzy duplicate skipped: {article['title']}")
            _add_related(unique_articles, article, index, normalized, batch_start_idx)
            seen_hashes.add(raw_hash)
            new_hashes.append(raw_hash)
            continue

        hash_to_idx[raw_hash] = len(unique_articles)
        unique_articles.append(article)
        index.add(normalized)
        seen_hashes.add(raw_hash)
        new_hashes.append(raw_hash)
        new_titles.append(article["title"])

    all_hashes = list(seen_hashes)
    _save_lines(SEEN_HASHES_FILE, all_hashes, max_lines=MAX_SEEN_HASHES)

    all_titles = seen_titles + new_titles
    _save_lines(SEEN_TITLES_FILE, all_titles, max_lines=MAX_SEEN_TITLES)

    logging.info(
        f"Deduplication: {len(articles)} input -> {len(unique_articles)} unique "
        f"({len(articles)} news reviewed)"
    )
    return unique_articles


def _merge_region(original, duplicate):
    """Merge feed_region from duplicate into the original article."""
    orig_region = original.get("feed_region", "Global")
    dup_region = duplicate.get("feed_region", "Global")
    if dup_region and dup_region != orig_region:
        existing = set(orig_region.split(","))
        existing.add(dup_region)
        existing.discard("Global")
        original["feed_region"] = ",".join(sorted(existing)) if existing else "Global"


def _add_related(unique_articles, duplicate_article, index, dup_normalized,
                 batch_start_idx):
    match_offset = index.find_best_match_index(
        dup_normalized, batch_start_idx
    )
    if 0 <= match_offset < len(unique_articles):
        original = unique_articles[match_offset]

        # Merge regions: combine feed_region from duplicate into original
        orig_region = original.get("feed_region", "Global")
        dup_region = duplicate_article.get("feed_region", "Global")
        if orig_region != dup_region:
            existing_regions = set(orig_region.split(","))
            existing_regions.add(dup_region)
            existing_regions.discard("Global")
            original["feed_region"] = ",".join(sorted(existing_regions)) if existing_regions else "Global"

        related = original.get("related_articles", [])
        related.append({
            "title": duplicate_article["title"],
            "link": duplicate_article["link"],
            "source": duplicate_article.get("source", ""),
        })
        original["related_articles"] = related
