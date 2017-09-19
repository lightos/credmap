"""
Site: Airbnb.com
Description: Online service to list, find, and rent short-term lodging.
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

    browser.visit('https://www.airbnb.com/login')

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

    for _ in browser.find_by_tag("button"):
        if _.text == "Log in":  # Rewrite to not rely on English text
            login_btn = _
            break

    login_btn.click()

    err_msg = browser.find_by_css(".alert-info").first.text if\
        browser.is_element_present_by_css(".alert-info") else None

    if err_msg and ("No account exists for this email" in err_msg
                    or "Invalid email" in err_msg):
        return {"authenticated": False, "msg": "invalid account"}
    if err_msg and "The password you entered is incorrect" in err_msg:
        return {"authenticated": False, "msg": "invalid password"}

    elements = browser.find_by_id("header")
    if elements and elements.first.has_class("logged_in"):
        return {"authenticated": True}
    elif browser.find_link_by_text("account.disabled@airbnb.com"):
        return {"authenticated": True, "msg": "account disabled"}
