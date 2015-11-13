#!/usr/bin/env python

"""
Copyright (c) 2015 Roberto Christopher Salgado Bjerre.

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

from __future__ import print_function

import re
import xml.etree.ElementTree
import cookielib

from time import strftime
from urllib import urlencode
from urllib2 import urlopen, ProxyHandler, Request, install_opener, HTTPHandler
from urllib2 import build_opener, quote, HTTPCookieProcessor, HTTPSHandler
from urlparse import urlsplit, urlunsplit, parse_qsl
from optparse import OptionParser
from getpass import getpass
from random import sample
from os import listdir, name
from os.path import isfile, join


NAME = "credmap"
VERSION = "v0.1"
URL = "https://github.com/lightos/credmap/"

# Maximum length of left option column in help listing
MAX_HELP_OPTION_LENGTH = 20

# Character used for progress rotator
ROTATOR_CHARS = "|/-\\"

# Operating System
WINDOWS = name == "nt"

# ANSI color codes
W = '\033[0m'
BW = '\033[1m'
R = '\033[31m'
G = '\033[32m'
O = '\033[33m'
B = '\033[34m'
P = '\033[35m'
C = '\033[36m'
GR = '\033[37m'

# Information levels
PLUS = "[%s+%s]" % (("", "") if WINDOWS else (G, W))
INFO = "[%si%s]" % (("", "") if WINDOWS else (C, W))
WARN = "[%s!%s] %sWarning%s:" % (("", "", "", "") if WINDOWS else (O, W, O, W))
ERROR = "[%sx%s] %sERROR%s:" % (("", "", "", "") if WINDOWS else (R, W, R, W))

BANNER_PASSWORDS = ("123456", "HUNTER2", "LOVE",
                    "SECRET", "ABC123", "GOD", "SEX")

BANNER = """               . .IIIII             .II
  I%sIIII. I  II  .    II..IIIIIIIIIIIIIIIIIIII
 .  .IIIIII  II             IIIIII%sIIIII  I.
    .IIIII.III I        IIIIIIIIIIIIIIIIIIIIIII
   .II%sII           II  .IIIII IIIIIIIIIIII. I
    IIIIII             IIII I  II%sIIIIIII I
    .II               IIIIIIIIIIIII  IIIIIIIII
       I.           .III%sIIII    I   II  I
         .IIII        IIIIIIIIIIII     .       I
          IIIII.          IIIIII           . I.
          II%sIII         IIIII             ..I  II .
           IIIIII          IIII...             IIII
            IIII           III. I            II%sII
            III             I                I  III
            II                                   I   .
             I                                        """

# Location of the folder containing the websites to test
SITES_DIR = "websites"

# Location of file containing user agents
USER_AGENTS_FILE = "agents.txt"

# Location of Git repository
GIT_REPOSITORY = "https://github.com/lightos/credmap.git"

# Variable used to store command parsed arguments
args = None

# Posible values in XML file
XML_ELEMENTS = ("url", "name", "description", "login_url", "invalid_account",
                "inactive_account", "valid_password", "invalid_password",
                "valid_response_header", "valid_response_header_type",
                "valid_response_header", "invalid_http_status", "headers",
                "cookies", "user_agent", "username_or_email", "custom_search",
                "login_parameter", "login_parameter_type", "multiple_params",
                "password_parameter", "password_parameter_type", "status",
                "csrf_token_name", "csrf_url", "csrf_setcookie_regex",
                "csrf_regex", "csrf_start", "csrf_end", "captcha_flag",
                "multiple_params_url", "valid_user_header", "csrf_token",
                "self.response_headers", "self.response_status", "data",
                "email_exception", "login_redirect", "login_redirect_type")

EXAMPLES = """
Examples:
./credmap.py --username janedoe --email janedoe@email.com
./credmap.py -u johndoe -e johndoe@email.com --exclude "github.com,twitter.com"
./credmap.py -u johndoe -p abc123 --only "linkedin.com, facebook.com"
./credmap.py -e janedoe@example.com --proxy "https://127.0.0.1:8080"
./credmap.py --list
"""


def print(*args, **kwargs):
    """
    Currently no purpose.
    """

    return __builtins__.print(*args, **kwargs)


class PROXY_TYPE:
    HTTP = "HTTP"
    HTTPS = "HTTPS"
    SOCKS4 = "SOCKS4"
    SOCKS5 = "SOCKS5"


class HTTP_HEADER:
    COOKIE = "Cookie"
    USER_AGENT = "User-agent"
    CONTENT_LENGTH = "Content-length"


class AttribDict(dict):
    """
    Gets and Sets attributes for a dict.
    """
    def __getattr__(self, name):
        return self.get(name)

    def __setattr__(self, name, value):
        return self.__setitem__(name, value)


class UserCredentials(object):
    """
    Populates user credentials.
    Might can this class.
    """
    def __init__(self, _args):
        self.username = _args.username
        self.email = _args.email
        self.password = _args.password


class Website(object):
    """
    Populates the Website object with data from the XML file.
    """
    def __init__(self, *data, **kwargs):
        for dictionary in data:
            for key in dictionary:
                setattr(self, key, dictionary[key])
        for key in kwargs:
            setattr(self, key, kwargs[key])

        for _ in XML_ELEMENTS:
            if not hasattr(self, _):
                setattr(self, _, None)

        self.status = {"status": 1, "msg": "%s instantiated" % self.name}

    def get_page(self, data=False, header=False):
        """
        Retrieves page content from a given target URL
        """

        headers = {}
        parsed_url = None
        page = None
        conn = None

        parsed_url = urlsplit(self.url)

        if self.user_agent is None:
            self.user_agent = "%s %s" % (NAME, VERSION)

        if not data:
            parsed_url = parsed_url._replace(
                query=urlencode(parse_qsl(parsed_url.query)))
            self.url = urlunsplit(parsed_url)
        else:
            self.data = urlencode(parse_qsl(self.data, 1), "POST")

        try:
            headers[HTTP_HEADER.USER_AGENT] = self.user_agent

            if header:
                headers.update(dict([tuple(_.split("=", 1))
                                     for _ in self.headers.split(";", 1)]))

            req = Request(self.url, self.data if data else None, headers)
            conn = urlopen(req)

            if not page:
                page = conn.read()

        except KeyboardInterrupt:
            raise

        except Exception, error:
            if hasattr(error, "read"):
                page = page or error.read()

            if (hasattr(error, "code") and self.invalid_http_status and
                    error.code == int(self.invalid_http_status)):
                pass
            elif args.verbose:
                if hasattr(error, "msg"):
                    print("%s msg '%s'." % (ERROR, error.msg))
                if hasattr(error, "reason"):
                    print("%s reason '%s'." % (ERROR, error.reason))
                if getattr(error, "message"):
                    print("%s message '%s'." % (ERROR, error.message))
                if hasattr(error, "code"):
                    print("%s error code '%d'." % (ERROR, error.code))
                if hasattr(error, "info"):
                    print("%s response headers '%s'." % (ERROR, error.info()))

        # NEED TO CLEAN THIS WHOLE PART UP
        self.status["status"] = 1 if conn else 0
        self.status["message"] = (conn.msg if conn and hasattr(conn, "msg")
                                  else error.msg if error and
                                  hasattr(error, "msg") else "Unknown error!")
        self.response_headers = (conn.info if conn and hasattr(conn, "info")
                                 else error.info if error and
                                 hasattr(error, "info") else "Unknown info!")
        self.response_status = (conn.code if conn and hasattr(conn, "code")
                                else error.code if error and
                                hasattr(error, "code") else "Unknown code!")

        return page

    def add_cookies(self, cookie_handler, cookies, url=None):
        """
        Add cookies to the specified cookie jar.
        Domain for the cookie can be specified via url.
        """
        domain = urlsplit(url or self.login_url)
        domain = ".%s.%s" % (domain.netloc.split(".")[-2],
                             domain.netloc.split(".")[-1])
        for _ in parse_qsl(cookies, 1):
            cookie = cookielib.Cookie(version=0, name=_[0], value=_[1],
                                      port=None, port_specified=False,
                                      domain=domain,
                                      domain_specified=True,
                                      domain_initial_dot=True, path='/',
                                      path_specified=True, secure=True,
                                      expires=None, discard=True, comment=None,
                                      comment_url=None, rest={}, rfc2109=False)
            cookie_handler.set_cookie(cookie)

    def perform_login(self, credentials, cookie_handler):
        """
        Parses CSRF token if available and performs login request.
        """

        if self.cookies:
            self.add_cookies(cookie_handler, self.cookies)

        if self.csrf_token_name:
            self.url = self.csrf_url
            csrf_response = self.get_page()

            if not csrf_response:
                if args.verbose:
                    print("%s problem receiving HTTP response "
                          "while fetching token!\n" % ERROR)
                return

            if self.csrf_regex or self.csrf_setcookie_regex:
                match = re.search(self.csrf_regex if self.csrf_regex
                                  else self.csrf_setcookie_regex,
                                  csrf_response if self.csrf_regex
                                  else str(cookie_handler), re.I)
                if match:
                    self.csrf_token = (match.group("token")
                                       if match.groupdict().has_key("token")
                                       else match.group(1))
                else:
                    self.status = {"status": 0, "msg": "No token"}
            else:
                start = csrf_response.find(self.csrf_start)
                if start == -1 and args.verbose:  # lvl 1 verbose
                    self.status = {"status": 0, "msg": "No token"}
                end = csrf_response.find(self.csrf_end,
                                         start+len(self.csrf_start))
                self.csrf_token = csrf_response[start+len(self.csrf_start):end]

            if self.status["msg"] == "No token" or not self.csrf_token:
                if args.verbose:
                    print("%s CSRF token not found. Skipping page...\n" % WARN)
                return

            if args.verbose:
                print("%s Authentication Token: \"%s\"" %
                      (INFO, color(self.csrf_token)))

        def replace_param(string, param, value, param_format=None):
            """
            Replace data in parameters with given string.
            Parameter format can be json or normal POST data.
            """
            if param_format == "json":
                return re.sub(r"(?P<json_replacement>\"%s\"\s*:\s*\"\s*)\"" %
                              param, "\\1%s\"" % value, string)
            else:
                return string.replace("%s=" % param, "%s=%s" % (param, value))

        if self.multiple_params:
            multiple_params_response = ""
            if(self.csrf_token_name and
               self.csrf_url == self.multiple_params_url):
                multiple_params_response = csrf_response
            else:
                self.url = self.multiple_params_url
                multiple_params_response = self.get_page()

            if not multiple_params_response:
                print("%s problem receiving HTTP response "
                      "while fetching params!\n" % ERROR)
                return

            for _ in self.multiple_params:
                regex = (_["regex"] if _.has_key("regex") else
                         r"<\w+\s*(\s*\w+\s*=\"[^\"]*\")*\s*name="
                         r"\"%s\"\s*(\s*\w+\s*=\"[^\"]*\")*\s*/?>"
                         % _["value"])
                match = re.search(regex, multiple_params_response)

                if not match:
                    if args.verbose:
                        print("%s match for \"%s\" was not found!"
                              % (WARN, color(_["value"])))
                    continue

                if "regex" in _:
                    value = (match.group("value")
                             if match.groupdict().has_key("value")
                             else match.group(1))
                elif "value" in _:
                    for attrib in match.groups():
                        attrib = str(attrib).strip().split("=", 1)
                        if attrib[0] == "value":
                            value = attrib[1].strip("\"")

                if not _.has_key("type"):
                    _["type"] = "data"

                if _["type"] == "data" and self.data:
                    self.data = replace_param(self.data, _["value"], value)
                elif _["type"] == "cookie":
                    self.add_cookies(cookie_handler, "%s=%s;" % (_["value"],
                                                                 value))
                else:
                    pass  # NEED TO REPLACE GET PARAMS

        if credentials.email and self.username_or_email in ("email", "both"):
            login = credentials.email
        elif(credentials.email and self.email_exception and
             self.username_or_email == "username" and
             re.search(self.email_exception, credentials.email)):
            login = credentials.email
        else:
            login = credentials.username

        # need to implement support for GET logins lulz

        if self.data:
            self.data = replace_param(self.data, self.login_parameter,
                                      login, self.login_parameter_type)
            self.data = replace_param(self.data, self.password_parameter,
                                      credentials.password,
                                      self.login_parameter_type)

        # need to be able to specify where tokens can be replaced
        if self.csrf_token:
            self.csrf_token = quote(self.csrf_token)
            if self.data:
                self.data = replace_param(self.data,
                                          self.csrf_token_name,
                                          self.csrf_token)
            if self.headers:
                self.headers = replace_param(self.headers,
                                             self.csrf_token_name,
                                             self.csrf_token)
            if self.cookies:
                self.cookies = replace_param(self.cookies,
                                             self.csrf_token_name,
                                             self.csrf_token)
                self.add_cookies(cookie_handler, self.cookies)

        self.url = self.login_url
        login_response = self.get_page(data=True if self.data else False,
                                       header=True if self.headers else False)

        if not login_response:
            if args.verbose:
                print("%s no response received! "
                      "Skipping to next site...\n" % WARN)
            return False

        if self.login_redirect:
            if self.login_redirect_type == "regex":
                self.url = re.search(self.login_redirect, login_response)
                self.url = (self.url.group("URL")
                            if self.url.groupdict().has_key("URL")
                            else self.url.group(1))
            else:
                self.url = self.login_redirect

            self.url = self.url.replace("\\", "")

            login_response = self.get_page(data=True if self.data else False,
                                           header=True if self.headers
                                           else False)

        if not login_response:
            if args.verbose:
                print("%s no response received during login redirect! "
                      "Skipping to next site...\n" % WARN)
            return False

        # The code for these IF checks need to be cleaned up

        # If invalid credentials http status code is returned
        if (self.invalid_http_status and self.response_status and
                int(self.invalid_http_status) == int(self.response_status)):
            if args.verbose:
                print("%s Credentials were incorrect.\n" % INFO)
            return False
        # If captcha flag is set and found in login response
        if self.captcha_flag and self.captcha_flag in login_response:
            if args.verbose:
                print("%s captcha detected! Skipping to next site...\n" % WARN)
            return False
        # If custom search is set and found in response
        if self.custom_search and re.search(self.custom_search['regex'],
                                            login_response):
            if args.verbose:
                print("%s %s\n" % (INFO, self.custom_search["value"]))
            return False
        # Valid password string in response
        if self.valid_password and self.valid_password in login_response:
            print("%s Credentials worked! Successfully logged in.\n" % PLUS)
            return True
        # Valid response header in Cookies
        elif (self.valid_response_header and self.valid_response_header
              in str(cookie_handler)):
            print("%s Credentials worked! Successfully logged in.\n" % PLUS)
            return True
        # Valid response header type REGEX
        elif (self.valid_response_header and
              self.valid_response_header_type == "regex" and
              re.search(self.valid_response_header,
                        str(self.response_headers))):
            print("%s Credentials worked! Successfully logged in.\n" % PLUS)
            return True
        # Valid response header for cookies type REGEX
        elif (self.valid_response_header and
              self.valid_response_header_type == "regex" and
              re.search(self.valid_response_header,
                        str(cookie_handler))):
            print("%s Credentials worked! Successfully logged in.\n" % PLUS)
            return True
        # Valid response header type normal
        elif (self.valid_response_header and self.valid_response_header
              in str(self.response_headers)):
            print("%s Credentials worked! Successfully logged in.\n" % PLUS)
            return True
        # Valid response header for cookies type normal
        elif (self.valid_response_header and self.valid_response_header
              in str(cookie_handler)):
            print("%s Credentials worked! Successfully logged in.\n" % PLUS)
            return True
        # Valid user header returned, but password is incorrect
        elif (self.valid_user_header and self.valid_user_header
              in str(self.response_headers)):  # Special case for Imgur
            if args.verbose:
                print("%s The provided user exists, "
                      "but the password was incorrect!\n" % INFO)
            return False
        # Invalid account string found in login response
        elif self.invalid_account and self.invalid_account in login_response:
            if args.verbose:
                print("%s The provided account doesn't exist on this site.\n"
                      % INFO)
            return False
        # User exists, but account isn't activate.
        elif self.inactive_account and self.inactive_account in login_response:
            if args.verbose:
                print("%s The user exists, but the account isn't activate.\n"
                      % INFO)
            return False
        # User exists, but invalid password string in login response
        elif (self.invalid_password and self.invalid_account
              and self.invalid_password in login_response):
            if args.verbose:
                print("%s The user exists, but the password is incorrect.\n"
                      % INFO)
            return False
        # Invalid password string in login response
        elif (self.invalid_password and not self.invalid_account
              and self.invalid_password in login_response):
            if args.verbose:
                print("%s The provided credentials are incorrect "
                      "or the account doesn't exist.\n" % INFO)
            return False
        # Unhandled case
        else:
            if args.verbose:
                print("%s Unable to login! Skipping to next site...\n" % WARN)
                # if verbose 2
                # print "this happens with a response that isn't handled"
            return False


def parse_args():
    """
    Parses command line arguments.
    """
    # Override epilog formatting
    OptionParser.format_epilog = lambda self, formatter: self.epilog

    parser = OptionParser(usage="usage: %prog --email EMAIL [options]",
                          epilog=EXAMPLES)

    parser.add_option("-v", "--verbose", action="count", dest="verbose",
                      help="display extra output information")

    parser.add_option("-u", "--username", dest="username",
                      help="set the username to test with")

    parser.add_option("-p", "--password", dest="password",
                      help="set the password to test with")

    parser.add_option("-e", "--email", dest="email",
                      help="set an email to test with")

    parser.add_option("-x", "--exclude", dest="exclude",
                      help="exclude sites from testing")

    parser.add_option("-o", "--only", dest="only",
                      help="test only listed sites")

    parser.add_option("-s", "--safe-urls", dest="safe_urls",
                      action="store_true",
                      help="only test sites that use HTTPS.")

    parser.add_option("-i", "--ignore-proxy", dest="ignore_proxy",
                      action="store_true",
                      help="ignore system default HTTP proxy")

    parser.add_option("--proxy", dest="proxy",
                      help="set proxy (e.g. \"socks5://192.168.1.2:9050\")")

    parser.add_option("--list", action="store_true", dest="list",
                      help="list available sites to test with")

    parser.formatter.store_option_strings(parser)
    parser.formatter.store_option_strings = lambda _: None

    for option, value in parser.formatter.option_strings.items():
        value = re.sub(r"\A(-\w+) (\w+), (--[\w-]+=(\2))\Z", r"\g<1>/\g<3>",
                       value)
        value = value.replace(", ", '/')
        if len(value) > MAX_HELP_OPTION_LENGTH:
            value = ("%%.%ds.." % (MAX_HELP_OPTION_LENGTH -
                                   parser.formatter.indent_increment)) % value
        parser.formatter.option_strings[option] = value

    args = parser.parse_args()[0]

    if not any((args.username, args.email, args.list)):
        parser.error("Required argument is missing. Use '-h' for help.")

    return args


def list_sites(extension=False):
    """
    List available sites for testing found in the websites folder.
    Read folder containing each website's XML files.
    """

    return [_ if extension else _.replace(".xml", "")
            for _ in listdir(SITES_DIR) if isfile(join(SITES_DIR, _))]


def populate_site(site):
    """
    Parse sites in XML files and return objects.
    """

    try:
        xml_tree = xml.etree.ElementTree.parse("%s/%s.xml" %
                                               (SITES_DIR, site)).getroot()
    except Exception:
        print("%s parsing XML file \"%s\". Skipping...\n" % (ERROR,
                                                             color(site, BW)))
        return

    site_properties = AttribDict()

    for _ in xml_tree:
        if _.tag == "multiple_params":
            site_properties["multiple_params"] = []
            site_properties["multiple_params_url"] = _.attrib["value"]
            continue
        if _.tag == "custom_search":
            site_properties["custom_search"] = {"regex": _.attrib["regex"],
                                                "value": _.attrib["value"]}
            continue
        if "value" in _.attrib:
            site_properties[_.tag] = _.attrib["value"]
        if "type" in _.attrib:
            site_properties["%s_type" % _.tag] = _.attrib["type"]

    if site_properties.multiple_params:
        for _ in xml_tree.iter('param'):
            site_properties.multiple_params.append(_.attrib)

    match = re.match(r"(?P<type>[^:]+)://[^.]+(\.\w+)*",
                     site_properties.login_url, re.I)

    if not match:
        print("%s unable to read URL for login in XML file for \"%s\". "
              "Skipping site..." % (ERROR, color(site_properties.name, BW)))
        return

    if args.safe_urls and match.group("type").upper() != PROXY_TYPE.HTTPS:
        if args.verbose:
            print("%s URL uses an unsafe transportation mechanism: \"%s\". "
                  "Skipping site...\n" % (WARN, match.group("type").upper()))
        return

    if(not site_properties.login_parameter or
       not site_properties.password_parameter):
        print("%s current XML file is missing parameter(s) for login. "
              "Skipping site...\n" % ERROR)
        return

    return site_properties


def color(text, color=GR):
    """
    Sets the text to a given color if not running under Windows.
    """

    if name == "nt":
        return text
    else:
        return "%s%s%s" % (color, text, W)


def main():
    """
    Initializes and executes the program
    """

    global args
    login_sucessful = []
    login_failed = []

    print("%s\n\n%s %s (%s)\n" % (
        BANNER % tuple([color(_) for _ in BANNER_PASSWORDS]),
        NAME, VERSION, URL))

    args = parse_args()

    if args.list:
        sites = list_sites()
        for _ in sites:
            print("- %s" % _)
        exit()

    if not args.password:
        args.password = getpass("%s Please enter password:" % INFO)
        print("")

    cookie_handler = cookielib.CookieJar()

    if args.ignore_proxy:
        proxy_handler = ProxyHandler({})
        opener = build_opener(HTTPHandler(), HTTPSHandler(), proxy_handler,
                              HTTPCookieProcessor(cookie_handler))
        install_opener(opener)

    elif args.proxy:
        match = re.search(r"(?P<type>[^:]+)://(?P<address>[^:]+)"
                          r":(?P<port>\d+)", args.proxy, re.I)
        if match:
            if match.group("type").upper() in (PROXY_TYPE.HTTP,
                                               PROXY_TYPE.HTTPS):
                proxy_handler = ProxyHandler({match.group("type"): args.proxy})
                opener = build_opener(
                    HTTPHandler(),
                    HTTPSHandler(),
                    proxy_handler,
                    HTTPCookieProcessor(cookie_handler))
                install_opener(opener)
            else:
                from thirdparty.socks import socks
                if match.group("type").upper() == PROXY_TYPE.SOCKS4:
                    socks.setdefaultproxy(socks.PROXY_TYPE_SOCKS4,
                                          match.group("address"),
                                          int(match.group("port")), True)
                elif match.group("type").upper() == PROXY_TYPE.SOCKS5:
                    socks.setdefaultproxy(socks.PROXY_TYPE_SOCKS5,
                                          match.group("address"),
                                          int(match.group("port")), True)
        else:
            print("%s wrong proxy format "
                  "(proper example: \"http://127.0.0.1:8080\")." % WARN)
            exit()
    else:
        opener = build_opener(HTTPHandler(),
                              HTTPSHandler(),
                              HTTPCookieProcessor(cookie_handler))
        install_opener(opener)

    with open(USER_AGENTS_FILE, 'r') as ua_file:
        args.user_agent = sample(ua_file.readlines(), 1)[0].strip()

    credentials = UserCredentials(args)

    sites = list_sites()

    if args.only:
        sites = [site for site in sites if site in args.only]
    elif args.exclude:
        sites = [site for site in sites if site not in args.exclude]

    print("%s Loaded %d %s to test." % (INFO, len(sites),
                                        "site" if len(sites) == 1
                                        else "sites"))
    print("%s Starting tests at: \"%s\"\n" % (INFO, color(strftime("%X"), BW)))

    for site in sites:
        _ = populate_site(site)
        if not _:
            continue
        target = Website(_)

        if (target.username_or_email == "email" and not args.email or
                target.username_or_email == "username" and not args.username):
            if args.verbose:
                print("%s Skipping \"%s\" since no \"%s\" was specified.\n" %
                      (INFO, color(target.name),
                       color(target.username_or_email)))
            continue

        print("%s Testing \"%s\"" % (INFO, color(target.name, BW)))

        if not target.user_agent:
            target.user_agent = args.user_agent

        if target.perform_login(credentials, cookie_handler):
            login_sucessful.append(target.name)
        else:
            login_failed.append(target.name)

    if not args.verbose:
        print()

    if len(login_sucessful) > 0 or len(login_failed) > 0:
        print("%s Succesfully logged into %s/%s websites." %
              (INFO, color(len(login_sucessful), BW),
               color(len(login_sucessful) + len(login_failed), BW)))
        print("%s An overall success rate of %s.\n" %
              (INFO, color("%%%s" % (100 * len(login_sucessful) / len(sites)),
                           BW)))

    if len(login_sucessful) > 0:
        print("%s The provided credentials worked on the following website%s: "
              "%s\n" % (PLUS, "s" if len(login_sucessful) != 1 else "",
                        ", ".join(login_sucessful)))

    print("%s Finished tests at: \"%s\"\n" % (INFO, color(strftime("%X"), BW)))


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("%s Ctrl-C pressed." % INFO)
