from playwright.sync_api import sync_playwright

APP_URL = "https://ai-phishing-detector.streamlit.app/"

with sync_playwright() as p:
    browser = p.chromium.launch()
    page = browser.new_page()
    page.goto(APP_URL, wait_until="networkidle", timeout=60000)

    # If the app was asleep, click the wake-up button
    try:
        page.get_by_text("Yes, get this app back up!").click(timeout=10000)
        page.wait_for_timeout(30000)
    except Exception:
        pass  # app was already awake

    page.wait_for_timeout(10000)  # stay a few seconds so the visit registers
    print("Visited:", page.title())
    browser.close()
