"""
Site: Ebay.com
Description: An e-commerce site, providing consumer to consumer and business
             to consumer sales services.
Author: @LightOS

-=Module Details=-
Account exists detection: False
Account disabled detection: N/A
Captcha detection: True
2FA detection: N/A
"""

__version__ = '0.1'
__author__ = 'LightOS'


def run(browser, creds):
    """Run current module"""

    email_input = None
    password_input = None

    browser.visit("https://signin.ebay.com/ws/eBayISAPI.dll?SignIn")

    for _ in browser.find_by_tag("input"):
        if "Email or username" in _["placeholder"]:
            email_input = _
        elif _["type"] == "password":
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

    if browser.find_link_by_partial_href("lgout=1") or\
       (browser.find_by_id("gh-ug") and
        browser.find_by_id("gh-ug").first.text[:3] == "Hi ") or\
       browser.find_link_by_text("Sign out"):
        return {"authenticated": True}

    if "reg.ebay.com/reg/UpdateContactInfo" in browser.url:
        return {"authenticated": True, "msg": "update contact info"}

    # Captcha detection
    if browser.find_by_id("frameBot"):
        return {"authenticated": False, "msg": "captcha"}

    if "that's not a match" in browser.find_by_id("errf").first.text or\
       browser.is_text_present("that's not a match"):
        return {"authenticated": False, "msg": "invalid account/password"}