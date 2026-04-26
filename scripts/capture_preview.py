"""Capture an animated GIF preview of the ThreatWatch dashboard.

Captures a sequence of dashboard states (briefing, trending threats,
exploits/KEV view, dark web, ransomware, APT tracker, article detail)
and stitches them into a single GIF for the README hero image.

Defaults to the local server (http://localhost:8098) so a clean rebuild
can refresh the asset without depending on a live deployment. Override
with DASHBOARD_URL=... for capturing the public site instead.
"""
import os
import time
from pathlib import Path

from playwright.sync_api import sync_playwright
from PIL import Image

OUTPUT_DIR = Path("/tmp/preview_frames")
OUTPUT_DIR.mkdir(exist_ok=True)

DASHBOARD_URL = os.environ.get("DASHBOARD_URL", "http://localhost:8098")
VIEWPORT = {"width": 1440, "height": 900}
FRAME_DURATION = 2400  # ms per frame in GIF — slow enough to actually read
SCROLL_SETTLE_S = 0.8
TAB_SETTLE_S = 1.2


def _shot(page, name):
    """Take a screenshot, return its path."""
    path = OUTPUT_DIR / f"{name}.png"
    page.screenshot(path=str(path))
    print(f"Captured: {name}")
    return path


def _scroll_main(page, y):
    page.evaluate(f"document.querySelector('#main-content').scrollTo({{top: {y}, behavior: 'instant'}})")
    time.sleep(SCROLL_SETTLE_S)


def _click_tab(page, tab):
    btn = page.query_selector(f'[data-tab="{tab}"]')
    if not btn:
        print(f"  (tab {tab!r} not found, skipping)")
        return False
    btn.click()
    time.sleep(TAB_SETTLE_S)
    return True


def capture_frames():
    frames = []
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page(viewport=VIEWPORT)
        page.goto(DASHBOARD_URL, wait_until="networkidle")
        time.sleep(3)  # let SSR data + skeleton dismissal settle

        # Frame 1 — Briefing card with TL;DR hero, escalation banner, threat-level chip.
        # AI mode is the default; ensure we're at the top.
        _scroll_main(page, 0)
        frames.append(_shot(page, "01_briefing_top"))

        # Frame 2 — scroll to Headlines + Trending Threats panel
        _scroll_main(page, 700)
        frames.append(_shot(page, "02_headlines_trending"))

        # Frame 3 — scroll further to Active Threat Actors / Sector Impact
        _scroll_main(page, 1400)
        frames.append(_shot(page, "03_actors_sectors"))

        # Frame 4 — EXPLOITS tab: surfaces CISA KEV badges + CVE pills
        if _click_tab(page, "exploits"):
            _scroll_main(page, 0)
            frames.append(_shot(page, "04_exploits_kev"))

        # Frame 5 — DARK WEB tab
        if _click_tab(page, "darkweb"):
            _scroll_main(page, 0)
            frames.append(_shot(page, "05_darkweb"))

        # Frame 6 — RANSOMWARE tracker
        if _click_tab(page, "ransom"):
            _scroll_main(page, 0)
            frames.append(_shot(page, "06_ransomware"))

        # Frame 7 — APT TRACKER
        if _click_tab(page, "apt"):
            _scroll_main(page, 0)
            frames.append(_shot(page, "07_apt"))

        # Frame 8 — back to briefing + open an article detail (shows IOC extraction,
        # CVE pills, COPY LINK + OPEN ARTICLE buttons).
        if _click_tab(page, "briefing"):
            _scroll_main(page, 0)
            cards = page.query_selector_all(".feed-card")
            if cards:
                cards[0].click()
                time.sleep(1.2)
                frames.append(_shot(page, "08_article_detail"))

        # Loop back to first frame so the GIF reads as a cycle.
        if frames:
            frames.append(frames[0])

        browser.close()
    return frames


def create_gif(frame_paths, output_path):
    if not frame_paths:
        print("No frames captured!")
        return
    images = []
    for fp in frame_paths:
        img = Image.open(fp)
        img = img.resize((1200, 750), Image.LANCZOS)
        img = img.convert("RGB").quantize(colors=128, method=Image.Quantize.MEDIANCUT)
        images.append(img)

    images[0].save(
        output_path,
        save_all=True,
        append_images=images[1:],
        duration=FRAME_DURATION,
        loop=0,
        optimize=True,
    )
    size_kb = Path(output_path).stat().st_size / 1024
    print(f"GIF saved to {output_path} ({size_kb:.0f} KB, {len(images)} frames)")


def save_screenshot(frame_paths, output_path):
    """Pick the briefing-top frame as the static screenshot.png hero."""
    if not frame_paths:
        return
    src = frame_paths[0]
    img = Image.open(src).convert("RGB")
    # Downscale keeps it crisp without ballooning the repo.
    img.thumbnail((1600, 1000), Image.LANCZOS)
    img.save(output_path, format="PNG", optimize=True)
    size_kb = Path(output_path).stat().st_size / 1024
    print(f"Screenshot saved to {output_path} ({size_kb:.0f} KB)")


if __name__ == "__main__":
    out_gif = Path("docs/preview.gif")
    out_gif.parent.mkdir(parents=True, exist_ok=True)
    print(f"Capturing dashboard frames from {DASHBOARD_URL}...")
    frames = capture_frames()
    print(f"\nCreating GIF from {len(frames)} frames...")
    create_gif(frames, str(out_gif))
    save_screenshot(frames, "docs/screenshot.png")
    print("Done!")
