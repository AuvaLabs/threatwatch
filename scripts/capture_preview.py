"""Capture an animated GIF preview of ThreatWatch intelligence operations.

Captures Mission Control and the primary operational workspaces,
then stitches them into a single GIF for the README hero image.

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


def _open(page, route):
    page.goto(f"{DASHBOARD_URL.rstrip('/')}{route}", wait_until="networkidle")
    time.sleep(TAB_SETTLE_S)


def capture_frames():
    frames = []
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page(viewport=VIEWPORT)
        _open(page, "/")
        frames.append(_shot(page, "01_mission_control"))

        for name, route in (
            ("02_ledger", "/ledger"),
            ("03_threats", "/threats"),
            ("04_hunts", "/hunts"),
            ("05_reports", "/reports"),
            ("06_automation", "/automation"),
        ):
            _open(page, route)
            frames.append(_shot(page, name))

        _open(page, "/sources")
        first_article = page.query_selector(".article-copy a")
        if first_article:
            first_article.click()
            page.wait_for_load_state("networkidle")
            time.sleep(SCROLL_SETTLE_S)
            frames.append(_shot(page, "07_article_detail"))

        _open(page, "/ledger")
        first_record = page.query_selector(".ledger-copy a")
        if first_record:
            first_record.click()
            page.wait_for_load_state("networkidle")
            time.sleep(SCROLL_SETTLE_S)
            frames.append(_shot(page, "08_ledger_record"))

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
