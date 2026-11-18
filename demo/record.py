"""Record the real operator dashboard after a local Compose smoke run."""
import argparse
import json
from pathlib import Path
import shutil
from tempfile import TemporaryDirectory
from urllib.request import urlopen

from playwright.sync_api import sync_playwright


def record(base, output, executable):
    with urlopen(base + "/api/overview", timeout=15) as response:
        state = json.load(response)
    complete = next(run for run in state["runs"] if run["state"] == "complete" and run["finding"])
    blocked = next(run for run in state["runs"] if run["state"] == "blocked")
    size = {"width": 1180, "height": 820}
    output.parent.mkdir(parents=True, exist_ok=True)
    with TemporaryDirectory() as tmp, sync_playwright() as playwright:
        browser = playwright.chromium.launch(executable_path=executable)
        context = browser.new_context(viewport=size, record_video_dir=tmp, record_video_size=size)
        page = context.new_page()
        page.goto(base)
        page.get_by_role("heading", name="Engagements", exact=True).wait_for()
        page.wait_for_timeout(2200)
        page.locator(f"a[href='/runs/{complete['id']}']").click()
        page.get_by_role("heading", name="Finding", exact=True).scroll_into_view_if_needed()
        page.wait_for_timeout(3300)
        page.get_by_role("heading", name="HTTP evidence", exact=True).evaluate(
            "(el) => el.scrollIntoView({block: 'start'})")
        page.wait_for_timeout(2600)
        page.get_by_text("Body preview", exact=False).last.click()
        page.wait_for_timeout(1800)
        page.evaluate("window.scrollTo(0,0)")
        page.wait_for_timeout(1600)
        page.goto(base + "/runs/" + blocked["id"])
        page.get_by_role("heading", name="Audit log", exact=True).scroll_into_view_if_needed()
        page.wait_for_timeout(2600)
        video = page.video
        context.close()
        video.save_as(output)
        browser.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", default="http://127.0.0.1:8000",
                        choices=["http://127.0.0.1:8000", "http://127.0.0.1:8800"])
    parser.add_argument("--output", type=Path, default=Path("private/reports/demo.webm"))
    parser.add_argument("--chrome", default=shutil.which("google-chrome"))
    args = parser.parse_args()
    record(args.base, args.output, args.chrome)
