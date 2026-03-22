"""Capture an animated GIF preview of the ThreatWatch dashboard."""

import time
from pathlib import Path
from playwright.sync_api import sync_playwright
from PIL import Image

OUTPUT_DIR = Path("/tmp/preview_frames")
OUTPUT_DIR.mkdir(exist_ok=True)

DASHBOARD_URL = "https://threatwatch.auvalabs.com"
VIEWPORT = {"width": 1440, "height": 900}
FRAME_DURATION = 2200  # ms per frame in GIF


def capture_frames():
    frames = []
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page(viewport=VIEWPORT)
        page.goto(DASHBOARD_URL, wait_until="networkidle")
        time.sleep(3)  # Let animations and data load settle

        # Frame 1: Dashboard overview (dark theme, default state)
        path1 = OUTPUT_DIR / "01_overview.png"
        page.screenshot(path=str(path1))
        frames.append(path1)
        print("Frame 1: Overview captured")

        # Frame 2: Toggle to AI briefing mode
        ai_btn = page.query_selector("#briefing-mode-toggle")
        if ai_btn:
            ai_btn.click()
            time.sleep(1.5)
            path2 = OUTPUT_DIR / "02_ai_briefing.png"
            page.screenshot(path=str(path2))
            frames.append(path2)
            print("Frame 2: AI Intelligence Briefing captured")

        # Frame 3: Scroll down to show more briefing content
        page.evaluate("document.querySelector('#main-content').scrollBy(0, 400)")
        time.sleep(0.8)
        path3 = OUTPUT_DIR / "03_briefing_scroll.png"
        page.screenshot(path=str(path3))
        frames.append(path3)
        print("Frame 3: Briefing scroll captured")

        # Scroll back up
        page.evaluate("document.querySelector('#main-content').scrollTo(0, 0)")
        time.sleep(0.5)

        # Frame 4: Switch to RESEARCH tab
        research_tab = page.query_selector("[data-tab='research']")
        if research_tab:
            research_tab.click()
            time.sleep(1)
            path4 = OUTPUT_DIR / "04_research.png"
            page.screenshot(path=str(path4))
            frames.append(path4)
            print("Frame 4: Research tab captured")

        # Frame 5: Switch to Ransomware tab
        ransom_tab = page.query_selector("[data-tab='ransom']")
        if ransom_tab:
            ransom_tab.click()
            time.sleep(1)
            path5 = OUTPUT_DIR / "05_ransomware.png"
            page.screenshot(path=str(path5))
            frames.append(path5)
            print("Frame 5: Ransomware tracker captured")

        # Frame 6: Switch to APT Tracker
        apt_tab = page.query_selector("[data-tab='apt']")
        if apt_tab:
            apt_tab.click()
            time.sleep(1)
            path6 = OUTPUT_DIR / "06_apt.png"
            page.screenshot(path=str(path6))
            frames.append(path6)
            print("Frame 6: APT tracker captured")

        # Frame 7: Back to overview, click article detail
        briefing_tab = page.query_selector("[data-tab='briefing']")
        if briefing_tab:
            briefing_tab.click()
            time.sleep(1)

        # Toggle back to normal briefing
        if ai_btn:
            ai_btn.click()
            time.sleep(0.5)

        articles = page.query_selector_all(".feed-item")
        if articles and len(articles) > 1:
            articles[1].click()
            time.sleep(1)
            path7 = OUTPUT_DIR / "07_article_detail.png"
            page.screenshot(path=str(path7))
            frames.append(path7)
            print("Frame 7: Article detail captured")

        # Loop back to first frame
        frames.append(path1)

        browser.close()

    return frames


def create_gif(frame_paths, output_path):
    images = []
    for fp in frame_paths:
        img = Image.open(fp)
        img = img.resize((1200, 750), Image.LANCZOS)
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
    output = Path("docs/preview.gif")
    output.parent.mkdir(parents=True, exist_ok=True)
    print("Capturing dashboard frames...")
    frame_paths = capture_frames()
    print(f"\nCreating GIF from {len(frame_paths)} frames...")
    create_gif(frame_paths, str(output))
    print("Done!")
