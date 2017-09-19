"""
Site: Amazon.com
Description: An e-commerce and cloud computing company.
Author: @LightOS

-=Module Details=-
Account exists detection: True
Account disabled detection: True
Captcha detection: N/A
2FA detection: N/A
"""

__version__ = '0.1'
__author__ = 'LightOS'


def run(browser, creds):
    """Run current module"""

    email_input = None
    password_input = None
    url = "https://www.amazon.com/ap/signin?_encoding=UTF8&openid.assoc_handl"\
        "e=usflex&openid.claimed_id=http%3A%2F%2Fspecs.openid.net%2Fauth%2F2."\
        "0%2Fidentifier_select&openid.identity=http%3A%2F%2Fspecs.openid.net"\
        "%2Fauth%2F2.0%2Fidentifier_select&openid.mode=checkid_setup&openid"\
        ".ns=http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0&openid.ns.pape=http"\
        "%3A%2F%2Fspecs.openid.net%2Fextensions%2Fpape%2F1.0&openid.pape"\
        ".max_auth_age=0&openid.return_to=https%3A%2F%2Fwww.amazon.com%2F%3F"\
        "ref_%3Dnav_signin"

    browser.visit(url)

    for _ in browser.find_by_tag("input"):
        if _["type"] == "email":
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

    # Captcha detection
    if browser.find_by_id("image-captcha-section") or\
       browser.is_text_present("enter the characters as they are shown"):
        return {"authenticated": False, "msg": "captcha"}

    if browser.find_by_id("nav-item-signout"):
        return {"authenticated": True}

    if browser.is_text_present("Your password is incorrect"):
        return {"authenticated": False, "msg": "invalid password"}

    if browser.is_text_present("not find an account with that email address"):
        return {"authenticated": False, "msg": "invalid account"}
