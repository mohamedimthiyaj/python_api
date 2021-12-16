from app import app
from flask import render_template
from flask import request, redirect
from flask import jsonify, make_response
import re
import validators
import subprocess
import shlex 
import json


@app.route("/")
def index():
    return render_template("public/index.html")

@app.route("/about")
def about():
    return render_template("public/about.html")

@app.route("/sign-up", methods=["GET", "POST"])
def sign_up():

    if request.method == "POST":

        req = request.form
        print(req)

        return redirect(request.url)

    return render_template("public/sign_up.html")


@app.route("/ping")
def ping():
    return render_template("public/ping.html")

@app.route("/whois")
def whois():
    return render_template("public/whois.html")

@app.route("/Subdomains")
def Subdomains():
    return render_template("public/Subdomains.html")

@app.route("/DNS_Zone_Transfer")
def DNS_Zone_Transfer():
    return render_template("public/DNS_Zone_Transfer.html")

@app.route("/Subdomaintko")
def Subdomaintko():
    return render_template("public/Subdomaintko.html")

@app.route("/web_site_Recon")
def web_site_Recon():
    return render_template("public/web_site_Recon.html")

@app.route("/website_scanner")
def website_scanner():
    return render_template("public/website_scanner.html")

@app.route("/waf_scanning")
def waf_scanning():
    return render_template("public/waf_scanning.html")

@app.route("/find_parameter")
def find_parameter():
    return render_template("public/find_parameter.html")

@app.route("/discover_hidden_directories_and_files")
def discover_hidden_directories_and_files():
    return render_template("public/discover_hidden_directories_and_files.html")

@app.route("/TCP_Scan")
def TCP_Scan():
    return render_template("public/TCP_Scan.html")

@app.route("/UDP_Scan")
def UDP_Scan():
    return render_template("public/UDP_Scan.html")

@app.route("/Wordpress_scan")
def Wordpress_scan():
    return render_template("public/Wordpress_scan.html")

@app.route("/lfi_exploit")
def lfi_exploit():
    return render_template("public/lfi_exploit.html")

@app.route("/open_redirect")
def open_redirect():
    return render_template("public/open_redirect.html")

@app.route("/sqli_exploit")
def sqli_exploit():
    return render_template("public/sqli_exploit.html")

@app.route("/ssrf_exploit")
def ssrf_exploit():
    return render_template("public/ssrf_exploit.html")

@app.route("/ssti_exploit")
def ssti_exploit():
    return render_template("public/ssti_exploit.html")

@app.route("/xss_exploit")
def xss_exploit():
    return render_template("public/xss_exploit.html")



@app.route("/guestbook/create-entry", methods=["POST"])
def create_entry():

#1.Ping Command Funtion
    def ping_cmd(target):
        output = subprocess.run(['ping', target, '-c 5'], capture_output=True,text=True)
        return output.stdout
#2.Whois Lookup Funtion
    def whois(target):
        output = subprocess.run(['whois', target], capture_output=True,text=True)
        return output.stdout
#3.Find Subdomains Funtion
    def find_subdomain(target):
        return "Find Subdomains"
#4.DNS Zone Transfer Funtion
    def dns_zone_transfer(target):
        return "DNS Zone Transfer"
#5.Subdomain Takeover Funtion
    def subdomain_tko(target):
        return "Subdomain Takeover"
#6.web site Recon Funtion
    def website_recon(target):
        return "web site Recon"
#7.web site scanner Funtion
    def website_scanner(target):
        return "web site scanner"
#8.waf-scanning Funtion
    def waf_scanning(target):
        return "waf scanning"
#9.find-parameter Funtion
    def find_parameter(target):
        return "find parameter"
#10.discover-hidden-directories-and-files
    def discover_hidden_directories_and_files(target):
        return "discover hidden directories and files"
#11.TCP Scan Funtion
    def tcp_scan(target):
        return "TCp Scan"
#12.UDP Scan Funtion
    def udp_scan(target):
        return "UDP Scan"
#13.Wordpress scan Funtion
    def wordpress_scan(target):
        return "Wordpress scan"
#14.lfi exploit Funtion
    def lfi_exploit(target):
        return "lfi exploit"
#15.open redirect exploit Funtion
    def open_redirect_exploit(target):
        return "open redirect exploit"
#16.sqli exploit tool sqlmap Funtion
    def sqli_exploit_tool_sqlmap(target):
        return "sqli exploit tool sqlmap"
#17.ssrf exploit Funtion
    def ssrf_exploit(target):
        return "ssrf exploit"
#18.ssti exploit Funtion
    def ssti_exploit(target):
        return "ssti exploit"
#19.xss exploit tool Funtion
    def xss_exploit_tool(target):
        return "xss_exploit_tool"


    def all_tools(target,tools_id):
        if tools_id == 101:
            #Ping Command
             return ping_cmd(target)
        elif tools_id == 102:
            #Whois Lookup
             return whois(target)
        elif tools_id == 103:
            #Find Subdomains
             return find_subdomain(target)
        elif tools_id == 104:
            #DNS Zone Transfer
             return dns_zone_transfer(target)
        elif tools_id == 105:
            #Subdomain Takeover
             return subdomain_tko(target)
        elif tools_id == 106:
            #web site Recon
             return website_recon(target)
        elif tools_id == 107:
            #web site scanner
             return website_scanner(target)
        elif tools_id == 108:
            #waf-scanning
             return waf_scanning(target)
        elif tools_id == 109:
            #find-parameter
             return find_parameter(target)
        elif tools_id == 110:
            #discover-hidden-directories-and-files
             return discover_hidden_directories_and_files(target)
        elif tools_id == 111:
            #TCP Scan
             return tcp_scan(target)
        elif tools_id == 112:
            #UDP Scan
             return udp_scan(target)
        elif tools_id == 113:
            #Wordpress scan
             return wordpress_scan(target)
        elif tools_id == 114:
            #lfi-exploit
             return lfi_exploit(target)
        elif tools_id == 115:
            #open-redirect-exploit
             return open_redirect_exploit(target)
        elif tools_id == 116:
            #sqli-exploit-tool-sqlmap
             return sqli_exploit_tool_sqlmap(target)
        elif tools_id == 117:
            #ssrf-exploit
             return ssrf_exploit(target)
        elif tools_id == 118:
            #ssti-exploit
             return ssti_exploit(target)
        elif tools_id == 119:
            #xss-exploit-tool
             return xss_exploit_tool(target)
        else:
            #not enter currect tool id
            return "Unknow tools_id"

    def alive(target):
        out_check = subprocess.run(['ping', target, '-c 1'], capture_output=True,text=True)
        if out_check.returncode == 0:
            # return "is domain"
            return all_tools(target,tools_id)
        elif out_check.returncode == 2:
            return "Target URL is not accessible. Please try a different hostnames, IP addresses and URL"



    def run(target_in):
            target = re.sub('https://|http://','',target_in)
            regex = "^((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])$"
            if validators.domain(target):
                # return "is domain"
                return alive(target)
            elif(re.search(regex, target)):
                # return "is domain"
                return alive(target)
            else:
                return "The target type is invalid. Valid target types are hostnames, IP addresses and URLs"

#error handel
    try:
        #Get input into end user
        output = request.get_json()

        #Check the input value name and number of input submit end user
        if len(output.keys()) == 2:
            target_in = str(output['target_in'])
            tools_id = int(output['tools_id'])
            #Starting tool valitation
            re_out = run(target_in)
            #save output into out variable
            out = {}
            out["target_in"] = re_out
            # out["tools_id"] = tools_id
        else:
            #check number of input 
            # return jsonify(message = "Bad Response") 
            return make_response(jsonify({"message" : "check number of input "}), 400)
    except KeyError:
        #check name is current or not
        # return jsonify(message = "Bad Response")
        return make_response(jsonify({"message" : "check name is current or not"}), 400)
    except ValueError:
        #check if the enter input is current data type or not
        # return jsonify(message = "Bad Response")
        return make_response(jsonify({"message" : "check if the enter input is current data type or not"}), 400)
    except AttributeError:
        #without param
        # return jsonify(message = "Bad Response")
        return make_response(jsonify({"message" : "without param"}), 400)
            

    # print(req)
    # rel = json.dumps(out)
    res = make_response(jsonify(out), 200)

    return res
    

