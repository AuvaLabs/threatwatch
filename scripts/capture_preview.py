"""Capture an animated GIF preview of the ThreatWatch dashboard."""

import time
from pathlib import Path
from playwright.sync_api import sync_playwright
from PIL import Image

OUTPUT_DIR = Path("/tmp/preview_frames")
OUTPUT_DIR.mkdir(exist_ok=True)

DASHBOARD_URL = "http://localhost:8098"
VIEWPORT = {"width": 1440, "height": 900}
FRAME_DURATION = 1800  # ms per frame in GIF


def capture_frames():
    frames = []
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page(viewport=VIEWPORT)
        page.goto(DASHBOARD_URL, wait_until="networkidle")
        time.sleep(2)  # Let animations settle

        # Frame 1: Dashboard overview (dark theme, default state)
        path1 = OUTPUT_DIR / "01_overview.png"
        page.screenshot(path=str(path1))
        frames.append(path1)
        print("Frame 1: Overview captured")

        # Frame 2: Scroll down to show briefing content
        page.evaluate("document.querySelector('#main-content').scrollBy(0, 400)")
        time.sleep(0.8)
        path2 = OUTPUT_DIR / "02_briefing.png"
        page.screenshot(path=str(path2))
        frames.append(path2)
        print("Frame 2: Briefing captured")

        # Frame 3: Click on an article to show detail view
        articles = page.query_selector_all(".feed-item")
        if articles and len(articles) > 1:
            articles[1].click()
            time.sleep(1)
            path3 = OUTPUT_DIR / "03_article_detail.png"
            page.screenshot(path=str(path3))
            frames.append(path3)
            print("Frame 3: Article detail captured")

            # Frame 4: Close detail, back to overview
            close_btn = page.query_selector(".detail-close")
            if close_btn:
                close_btn.click()
                time.sleep(0.8)

        # Frame 5: Switch to light theme
        theme_btn = page.query_selector("#theme-toggle, .theme-toggle, [onclick*='theme']")
        if theme_btn:
            theme_btn.click()
            time.sleep(0.8)
            path5 = OUTPUT_DIR / "05_light_theme.png"
            page.screenshot(path=str(path5))
            frames.append(path5)
            print("Frame 5: Light theme captured")

            # Switch back to dark
            theme_btn.click()
            time.sleep(0.5)

        # Frame 6: Click a region filter
        region_btns = page.query_selector_all(".region-btn, [data-region]")
        for btn in region_btns:
            text = btn.inner_text().strip()
            if "EMEA" in text or "NA" in text:
                btn.click()
                time.sleep(0.8)
                path6 = OUTPUT_DIR / "06_region_filter.png"
                page.screenshot(path=str(path6))
                frames.append(path6)
                print(f"Frame 6: Region filter ({text}) captured")
                break

        # Back to overview for loop
        page.evaluate("document.querySelector('#main-content').scrollTo(0, 0)")
        time.sleep(0.5)
        frames.append(path1)  # Loop back to first frame

        browser.close()

    return frames


def create_gif(frame_paths, output_path):
    images = []
    for fp in frame_paths:
        img = Image.open(fp)
        # Reduce size for reasonable GIF file size
        img = img.resize((1200, 750), Image.LANCZOS)
        # Convert to palette mode for GIF
        img = img.convert("RGB").quantize(colors=128, method=Image.Quantize.MEDIANCUT)
        images.append(img)

    if not images:
        print("No frames captured!")
        return

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


if __name__ == "__main__":
    print("Capturing dashboard frames...")
    frame_paths = capture_frames()
    print(f"\nCreating GIF from {len(frame_paths)} frames...")
    create_gif(frame_paths, "/home/deploy/threatTI/docs/preview.gif")
    print("Done!")
