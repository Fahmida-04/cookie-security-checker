from flask import Flask, render_template, request, jsonify
import requests
from urllib.parse import urlparse

app = Flask(__name__)

# Validate that the URL is correctly formed and uses http or https
def validate_url(url):
    if not url:
        return False, "Please enter a website URL."

    if not url.startswith("http://") and not url.startswith("https://"):
        url = "https://" + url

    parsed = urlparse(url)
    if parsed.scheme not in ["http", "https"] or not parsed.netloc:
        return False, "Invalid URL format. Use http:// or https:// and a valid domain."

    return True, url

# Perform the HTTP request and return cookie data with response metadata
def scan_website(url):
    headers = {
        "User-Agent": "Mozilla/5.0 (compatible; CookieSecurityChecker/1.0; +https://example.com)"
    }
    try:
        response = requests.get(url, headers=headers, timeout=10, allow_redirects=True, verify=True)
        cookies = response.cookies
        cookie_data = []
        for cookie in cookies:
            http_only = False
            if hasattr(cookie, "has_nonstandard_attr"):
                http_only = cookie.has_nonstandard_attr("HttpOnly")
            if not http_only and hasattr(cookie, "_rest"):
                http_only = bool(cookie._rest.get("HttpOnly"))

            cookie_data.append({
                "name": cookie.name,
                "value": cookie.value,
                "secure": getattr(cookie, "secure", False),
                "httponly": http_only,
                "samesite": cookie._rest.get("SameSite", "None") if hasattr(cookie, "_rest") else "None",
                "domain": getattr(cookie, "domain", None),
                "path": getattr(cookie, "path", None),
                "expires": getattr(cookie, "expires", None),
                "max_age": cookie._rest.get("Max-Age") if hasattr(cookie, "_rest") else None
            })
        return {
            "success": True,
            "url": response.url,
            "status_code": response.status_code,
            "cookies": cookie_data,
            "is_https": response.url.startswith("https://")
        }
    except requests.exceptions.SSLError:
        return {"success": False, "error": "SSL error: the website certificate could not be verified."}
    except requests.exceptions.ConnectTimeout:
        return {"success": False, "error": "Connection timeout: the website took too long to respond."}
    except requests.exceptions.ReadTimeout:
        return {"success": False, "error": "Read timeout: the website response was too slow."}
    except requests.exceptions.ConnectionError:
        return {"success": False, "error": "Connection error: could not reach the website."}
    except requests.exceptions.RequestException as exc:
        return {"success": False, "error": f"Request failed: {str(exc)}"}

# Analyze cookies and detect configuration issues
def analyze_cookies(cookie_data, is_https):
    analysis_results = []
    issues = []

    for cookie in cookie_data:
        missing_secure = not cookie.get("secure", False)
        missing_httponly = not cookie.get("httponly", False)
        same_site = cookie.get("samesite") or "None"
        if same_site == "":
            same_site = "None"

        risk_points = 0
        issue_messages = []

        if missing_secure:
            risk_points += 25
            issue_messages.append({
                "issue": "Missing Secure attribute",
                "explanation": "The cookie can be sent over unencrypted HTTP if the website also supports non-HTTPS access.",
                "recommendation": "Set Secure=True so the browser only sends this cookie over HTTPS."
            })
        if missing_httponly:
            risk_points += 25
            issue_messages.append({
                "issue": "Missing HttpOnly attribute",
                "explanation": "A cookie without HttpOnly may be read by JavaScript in the browser.",
                "recommendation": "Use HttpOnly=True to reduce exposure to client-side scripts."
            })
        if same_site.lower() not in ["lax", "strict"]:
            risk_points += 20
            issue_messages.append({
                "issue": "Missing or weak SameSite attribute",
                "explanation": "SameSite helps protect cookies during cross-site requests and reduce CSRF risks.",
                "recommendation": "Set SameSite=Lax or SameSite=Strict when appropriate for this cookie."
            })

        if not cookie.get("domain"):
            risk_points += 5
            issue_messages.append({
                "issue": "Missing domain attribute",
                "explanation": "The domain controls where the cookie is valid. Missing domain may allow broader use than intended.",
                "recommendation": "Set a specific domain or leave it as the default host-only cookie."
            })

        if not cookie.get("path"):
            risk_points += 5
            issue_messages.append({
                "issue": "Missing path attribute",
                "explanation": "A missing path can make the cookie available to more URLs than necessary.",
                "recommendation": "Set a path value that is as restrictive as possible."
            })

        if not cookie.get("expires") and not cookie.get("max_age"):
            risk_points += 10
            issue_messages.append({
                "issue": "Session cookie with no expiration",
                "explanation": "Session cookies end when the browser closes, which may be okay, but persistent cookies should have expiration or Max-Age.",
                "recommendation": "Review whether the cookie should expire or use Max-Age to limit its lifetime."
            })

        if is_https:
            risk_points -= 5

        if risk_points < 0:
            risk_points = 0
        if risk_points > 100:
            risk_points = 100

        risk_level = "Low"
        if risk_points >= 60:
            risk_level = "High"
        elif risk_points >= 30:
            risk_level = "Medium"

        if issue_messages:
            for issue in issue_messages:
                issues.append({
                    "cookie": cookie.get("name"),
                    "issue": issue["issue"],
                    "explanation": issue["explanation"],
                    "recommendation": issue["recommendation"]
                })

        analysis_results.append({
            "name": cookie.get("name"),
            "secure": "Yes" if cookie.get("secure") else "No",
            "httponly": "Yes" if cookie.get("httponly") else "No",
            "samesite": same_site.title(),
            "domain": cookie.get("domain") or "(not set)",
            "path": cookie.get("path") or "(not set)",
            "expires": cookie.get("expires") or cookie.get("max_age") or "Session",
            "risk_level": risk_level,
            "risk_points": risk_points,
            "issues": issue_messages
        })

    return analysis_results, issues

# Calculate overall score from cookie analysis results
def calculate_security_score(analysis_results, is_https):
    if not analysis_results:
        return {
            "score": 100 if is_https else 90,
            "risk_category": "Low",
            "issues_found": 0
        }

    total_points = sum(result["risk_points"] for result in analysis_results)
    max_points = len(analysis_results) * 100
    score = max(0, 100 - int((total_points / max_points) * 100))

    if score >= 80:
        category = "Low"
    elif score >= 50:
        category = "Medium"
    else:
        category = "High"

    return {
        "score": score,
        "risk_category": category,
        "issues_found": sum(len(result["issues"]) for result in analysis_results)
    }

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/scan", methods=["POST"])
def scan():
    data = request.get_json() or {}
    url = data.get("url", "")

    is_valid, validated_url_or_error = validate_url(url)
    if not is_valid:
        return jsonify({"success": False, "error": validated_url_or_error})

    scan_result = scan_website(validated_url_or_error)
    if not scan_result.get("success"):
        return jsonify({"success": False, "error": scan_result.get("error")})

    cookies = scan_result.get("cookies", [])
    if not cookies:
        return jsonify({"success": True, "message": "No cookies were set by this website.", "cookies": [], "summary": {"score": 100, "risk_category": "Low", "issues_found": 0, "cookie_count": 0}, "issues": []})

    analysis_results, issues = analyze_cookies(cookies, scan_result.get("is_https", False))
    summary = calculate_security_score(analysis_results, scan_result.get("is_https", False))
    summary["cookie_count"] = len(analysis_results)
    summary["status_code"] = scan_result.get("status_code")
    summary["scanned_url"] = scan_result.get("url")
    summary["https"] = scan_result.get("is_https")

    return jsonify({
        "success": True,
        "cookies": analysis_results,
        "issues": issues,
        "summary": summary
    })

if __name__ == "__main__":
    app.run(debug=True)
