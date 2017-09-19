"""
Site: Bitbucket.org
Description: Web-based Git repository hosting service.
Author: @LightOS

-=Module Details=-
Account exists detection: False
Account disabled detection: N/A
Captcha detection: N/A
2FA detection: N/A
"""

__version__ = '0.1'
__author__ = 'LightOS'


def run(browser, creds):
    """Run current module"""

    email_input = None
    password_input = None

    browser.visit("https://bitbucket.org/account/signin/")

    email_input = browser.find_by_id("js-email-field").first\
        if browser.find_by_id("js-email-field") else None
    for _ in browser.find_by_tag("input"):
        if _["type"] == "password":
            password_input = _
            break

    if not email_input or not password_input:
        return {"authenticated": False, "msg": "broken"}

    email_input.fill(creds["username"])
    password_input.fill(creds["password"])

    for _ in browser.find_by_tag("input"):
        if _["type"] == "submit":
            login_btn = _
            break

    login_btn.click()

    if browser.find_link_by_href("/account/signout/") or\
       browser.find_by_id("log-out-link") or\
       browser.find_link_by_partial_href("https://id.atlassian.com/logout"):
        return {"authenticated": True}

    for _ in browser.find_by_tag("p"):
        if "email address or password you entered is incorrect" in _.text:
            return {"authenticated": False, "msg": "invalid account/password"}

    # Captcha detection
    if browser.find_by_id("image-captcha-section"):
        return {"authenticated": False, "msg": "captcha"}
