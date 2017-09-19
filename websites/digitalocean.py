"""
Site: Digitalocean.com
Description: "DigitalOcean is a cloud infrastructure provider that provisions virtual servers.
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

    browser.visit("https://cloud.digitalocean.com/login")

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

    if browser.find_link_by_href("/logout") or\
       browser.find_link_by_partial_href("/settings/profile"):
        return {"authenticated": True}

    if browser.find_by_tag("li") and\
       "Invalid email or password" in browser.find_by_tag("li").first.text:
        return {"authenticated": False, "msg": "invalid account/password"}
