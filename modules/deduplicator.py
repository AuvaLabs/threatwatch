import hashlib
import logging
import re
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

# CVE identifiers — articles with different CVEs are always distinct incidents
_CVE_RE = re.compile(r"CVE-\d{4}-\d+", re.IGNORECASE)

# Minimum number of meaningful words (post-stop-word) required to attempt fuzzy
# matching. Titles shorter than this use exact-match only, preventing false dedup
# on very short headings.
_MIN_FUZZY_WORDS = 3

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
        self._raw_titles = []      # original (pre-normalize) for CVE extraction
        self._word_counts = []     # meaningful word count (post-stop-word) for each entry

    def add(self, normalized_title, raw_title=None):
        idx = len(self._normalized_titles)
        shingles = _make_word_shingles(normalized_title)
        word_count = len([w for w in normalized_title.split() if w not in _STOP_WORDS])
        self._title_shingles.append(shingles)
        self._normalized_titles.append(normalized_title)
        self._raw_titles.append(raw_title or normalized_title)
        self._word_counts.append(word_count)
        for s in shingles:
            if s not in self._shingle_to_indices:
                self._shingle_to_indices[s] = []
            self._shingle_to_indices[s].append(idx)
        return idx

    def _incoming_word_count(self, normalized_title):
        return len([w for w in normalized_title.split() if w not in _STOP_WORDS])

    def is_fuzzy_duplicate(self, normalized_title, raw_title=None,
                           threshold=FUZZY_DEDUP_THRESHOLD):
        shingles = _make_word_shingles(normalized_title)

        # Too few meaningful words in the incoming title — exact match only
        if self._incoming_word_count(normalized_title) < _MIN_FUZZY_WORDS:
            return normalized_title in self._normalized_titles

        incoming_cves = set(
            m.upper() for m in _CVE_RE.findall(raw_title or normalized_title)
        )

        # Gather candidates: titles sharing at least one word shingle
        candidate_set = set()
        for s in shingles:
            for idx in self._shingle_to_indices.get(s, ()):
                candidate_set.add(idx)

        for idx in candidate_set:
            existing = self._normalized_titles[idx]
            if normalized_title == existing:
                return True

            # Skip stored entries that are too short — a 2-word stored title would
            # match everything that mentions those 2 words (containment false positives)
            if self._word_counts[idx] < _MIN_FUZZY_WORDS:
                continue

            # CVE guard: if both titles have CVE IDs and they differ, these are
            # distinct vulnerability reports — never merge them as duplicates
            if incoming_cves:
                existing_cves = set(
                    m.upper() for m in _CVE_RE.findall(self._raw_titles[idx])
                )
                if existing_cves and incoming_cves != existing_cves:
                    continue

            similarity = _word_overlap_ratio(shingles, self._title_shingles[idx])
            if similarity >= threshold:
                logging.info(
                    f"Fuzzy duplicate ({similarity:.2f}): "
                    f"'{normalized_title}' ~ '{existing}'"
                )
                return True
        return False

    def find_best_match_index(self, normalized_title, start_idx, raw_title=None,
                              threshold=FUZZY_DEDUP_THRESHOLD):
        shingles = _make_word_shingles(normalized_title)
        if self._incoming_word_count(normalized_title) < _MIN_FUZZY_WORDS:
            return -1

        incoming_cves = set(
            m.upper() for m in _CVE_RE.findall(raw_title or normalized_title)
        )

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

            if self._word_counts[idx] < _MIN_FUZZY_WORDS:
                continue

            # CVE guard
            if incoming_cves:
                existing_cves = set(
                    m.upper() for m in _CVE_RE.findall(self._raw_titles[idx])
                )
                if existing_cves and incoming_cves != existing_cves:
                    continue

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
    # Load hashes as ordered list (preserves insertion order for correct LRU eviction)
    # and also as a set for O(1) lookup.
    seen_hashes_ordered = _load_lines(SEEN_HASHES_FILE)
    seen_hashes = set(seen_hashes_ordered)
    seen_titles = _load_lines(SEEN_TITLES_FILE)

    # Build shingle index from previously seen titles (raw title = normalized for old entries)
    index = ShingleIndex()
    for t in seen_titles:
        index.add(normalize_title(t), raw_title=t)

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

        raw_title = article["title"]
        normalized = normalize_title(raw_title)

        # Skip fuzzy dedup for dark web articles (structured titles with shared words)
        is_darkweb = article.get("darkweb", False)
        if not is_darkweb and index.is_fuzzy_duplicate(normalized, raw_title=raw_title):
            logging.info(f"Fuzzy duplicate skipped: {raw_title}")
            _add_related(unique_articles, article, index, normalized,
                         raw_title, batch_start_idx)
            seen_hashes.add(raw_hash)
            new_hashes.append(raw_hash)
            continue

        hash_to_idx[raw_hash] = len(unique_articles)
        unique_articles.append(article)
        index.add(normalized, raw_title=raw_title)
        seen_hashes.add(raw_hash)
        new_hashes.append(raw_hash)
        new_titles.append(raw_title)

    # Preserve insertion order: old hashes first, new appended at end.
    # _save_lines trims from the front (oldest) when over MAX_SEEN_HASHES.
    all_hashes = seen_hashes_ordered + new_hashes
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
                 dup_raw_title, batch_start_idx):
    match_offset = index.find_best_match_index(
        dup_normalized, batch_start_idx, raw_title=dup_raw_title
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
