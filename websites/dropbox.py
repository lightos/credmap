"""
Site: Dropbox.com
Description: Dropbox is a file hosting and sharing website.
Author: @LightOS

-=Module Details=-
Account exists detection: N/A
Account disabled detection: N/A
Captcha detection: True
2FA detection: N/A
"""

__version__ = '0.1'
__author__ = 'LightOS'


def run(browser, creds):
    """Run current module"""

    email_input = None
    password_input_input = None

    browser.visit('https://dropbox.com/login')

    for _ in browser.find_by_tag("input"):
        if _["type"] == "email":
            email_input = _
        elif _["type"] == "password":
            password_input = _
            break

    if not email_input or not password_input:
        return {"authenticated": False, "msg": "broken"}

    # Re-Captcha detection
    if browser.find_by_id("recaptcha_challenge_image"):
        return {"authenticated": False, "msg": "captcha"}
    for _ in browser.find_by_tag("iframe"):
        if "google.com/recaptcha/" in _["src"]:
            return {"authenticated": False, "msg": "captcha"}

    email_input.fill(creds["username"])
    password_input.fill(creds["password"])

    for _ in browser.find_by_tag("button"):
        if _.text == "Sign in":  # Rewrite to not rely on English text
            _.click()
            break

    if browser.find_by_id("page-sidebar"):
        return {"authenticated": True}

    return {"authenticated": False, "msg": "invalid account/password"}
