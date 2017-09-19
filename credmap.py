#!/usr/bin/env python

"""
Copyright (c) 2017 Roberto Christopher Salgado Bjerre.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"),
to deal in the Software without restriction, including without limitation the
rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
sell copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""

import os
from glob import glob
from time import time
from re import match

from importlib import import_module
from splinter import Browser

# Location of the folder containing the websites to test
SITES_DIR = "websites"

# Location of file containing user agents
USER_AGENTS_FILE = "agents.txt"

INFO = ""

executable_path = {'executable_path':
                   r'C:\Python27\phantomjs-2.1.1-windows\bin\phantomjs.exe'}
username = ""
password = ""

if not username or not password:
    print "input credentials"
    exit()

credentials = {"username": username, "password": password}

def main():
    """
    Initializes and executes the program.
    """
    websites = None
    agent = "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:40.0)"\
        "Gecko/20100101 Firefox/45.1"
    browser = Browser('phantomjs', service_log_path=os.path.devnull,
                      user_agent=agent, **executable_path)
    #browser = Browser('chrome')
    #websites = ["amazon"]
    if not websites:
        websites = [match(r"websites\\(\w+).py", _).group(1)
                    for _ in glob("%s/*.py" % SITES_DIR)
                    if '__init__' not in _]
    for _ in websites:
        website = import_module(".%s" % _, SITES_DIR)
        print "Running: %s" % website
        # try catch here
        print website.run(browser, credentials)

    browser.quit()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n%s Ctrl-C pressed." % INFO)
