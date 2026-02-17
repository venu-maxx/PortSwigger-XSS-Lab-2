# PortSwigger Web Security Academy Lab Report: Stored XSS into HTML Context with Nothing Encoded




**Report ID:** PS-LAB-XSS-002  

**Author:** Venu Kumar (Venu)  

**Date:** February 09, 2026  

**Lab Level:** Apprentice  

**Lab Title:** Stored XSS into HTML context with nothing encoded



## Executive Summary:

**Vulnerability Type:** Stored Cross-Site Scripting (XSS)  

**Severity:** High (CVSS 3.1 Score: ~7.1 – AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N – persistent nature increases risk; lab solves on alert execution)

**Description:** A stored XSS vulnerability exists in the blog post comment functionality. User input (comment body, name, email, website) is stored in the database and reflected directly into the HTML response without any encoding, sanitization, or filtering. This allows persistent injection of arbitrary HTML/JavaScript that executes for every viewer of the blog post.

**Impact:** Any user viewing the affected blog post executes the malicious script (e.g., cookie theft, session hijacking, keylogging, phishing overlays, or defacement). In production, attackers could target multiple users persistently without further interaction.

**Status:** Exploited in controlled lab environment only; no real-world impact. This report is for educational purposes.



## Environment and Tools Used:

**Target:** Simulated blog from PortSwigger Web Security Academy (e.g., `https://*.web-security-academy.net`)  

**Browser:** Google Chrome (Version 120.0 or similar)  

**Tools:** Built-in browser developer tools (Inspect Element, Console) 
Optional: Burp Suite Community Edition (for request inspection if needed)  

**Operating System:** Windows 11  

**Test Date/Time:** February 09, 2026, approximately 09:09 PM IST



## Methodology:

Conducted following ethical hacking best practices in a safe, simulated environment.

1. Accessed the lab via the "Access the lab" button in PortSwigger Web Security Academy.  
2. Navigated to a blog post with the comment section (usually at the bottom).  
3. Entered a test comment with normal text → submitted → observed reflection in page without changes (no encoding).  
4. Injected XSS payload: `<script>alert(1)</script>` in the comment field (filled name/email/website with dummy values).  
5. Submitted comment → refreshed or revisited the blog post → JavaScript executed, showing alert popup.  
6. Lab solved (green banner: "Congratulations, you solved the lab!").



## Detailed Findings:

**Vulnerable Functionality:** Blog post comment form (stored via POST, reflected on GET/view)

**Original Input (Safe Test):**

GET / HTTP/2
Host: 0ab6002104c82cd880e6030200040032.web-security-academy.net
Cookie: session=Q4ka2Rc7D4qzf8w2f5kw5e7Yvjeo0SvE
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36
Accept: text/html,application/xhtml+xml;q=0.9,*/*;q=0.8



**Reflected Output:**

HTTP/2 200 OK
Content-Type: text/html; charset=utf-8
Content-Length: 8141
Set-Cookie: session=Q4ka2Rc7D4qzf8w2f5kw5e7Yvjeo0SvE; Secure; HttpOnly; SameSite=None

<!DOCTYPE html>
<html>
<head>
    <title>Stored XSS into HTML context with nothing encoded</title>
</head>
<body>
    <!-- Lab header: "Not solved" status -->
    
    <!-- Blog post list: 10 posts with titles/images -->
    <div class="blog-post">
        <a href="/post?postId=10"><img src="/image/blog/posts/16.jpg"></a>
        <h2>Open Sans - I love You</h2>
        <p>...</p>
        <a href="/post?postId=10">View post</a>
    </div>
    <!-- 9 more similar blog posts (postId 1-9) -->
</body>
</html>


Modified request 1:

GET /post/comment/confirmation?postId=10 HTTP/2
Host: 0ab6002104c82cd880e6030200040032.web-security-academy.net
Cookie: session=Q4ka2Rc7D4qzf8w2f5kw5e7Yvjeo0SvE
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36
Referer: https://0ab6002104c82cd880e6030200040032.web-security-academy.net/post?postId=10
Accept: text/html,application/xhtml+xml;q=0.9,*/*;q=0.8


Response:

HTTP/2 200 OK
Content-Type: text/html; charset=utf-8
Content-Length: 5881
X-Frame-Options: SAMEORIGIN

<!DOCTYPE html>
<html>
<head>
    <title>Stored XSS into HTML context with nothing encoded</title>
</head>
<body>
    <!-- Lab header: "SOLVED" status + celebration message -->
    
    <h1>Thank you for your comment!</h1>
    <p>Your comment has been submitted.</p>
    <a href="/post?postId=10">Back to blog</a>
</body>
</html>



Proof of Exploitation:


![Proof of XSS  Error](https://github.com/venu-maxx/PortSwigger-XSS-Lab-2/blob/2378f4879b7fbf4db33d4a72f5bd8aa3d35acd7c/PortSwigger-XSS-Lab-2%20Error.png)

Figure 1: Payload submitted in comment form (name, email, website filled as dummy).


![Proof of Successful XSS Exploitation](https://github.com/venu-maxx/PortSwigger-XSS-Lab-2/blob/53836a3ab291c2623a172486710fd800e156733c/Portswigger%20XSS%20Lab%202%20success.png)

Figure 2: JavaScript alert(1) pops up when viewing the blog post.


![Lab Solved Congratulations](https://github.com/venu-maxx/PortSwigger-XSS-Lab-2/blob/308471f2b2afb6574888da8121b641cfcd13688c/Portswigger%20XSS%20Lab%202%20Completed.png)

Figure 3: PortSwigger Academy confirmation – "Congratulations, you solved the lab!"


Exploitation Explanation:

The application stores comment data without server-side sanitization and outputs it directly into HTML context (e.g., between <p> or <div> tags) without HTML-encoding characters like < > " ' &. This allows arbitrary tag/script injection. No CSP, WAF, or output encoding prevents execution. Payload executes persistently for all viewers.


Risk Assessment:

Likelihood of Exploitation: High (simple submission, persistent reflection, no protections).
Potential Impact: High — persistent code execution across users; enables advanced attacks like session theft or malware delivery.
Affected Components: Comment storage and rendering on blog post pages.



Recommendations for Remediation:

Implement output encoding (HTML-encode all user-controlled data before insertion into HTML using libraries like OWASP Java Encoder, DOMPurify, or built-in functions).
Use Content Security Policy (CSP) with strict directives (e.g., nonce-based scripts or script-src 'self').
Sanitize input server-side (strip dangerous tags/attributes if encoding insufficient).
Deploy Web Application Firewall (WAF) with XSS signatures (though not sufficient alone).
Perform regular security testing (Burp Scanner, OWASP ZAP, manual review) and code audits.



Conclusion and Lessons Learned:

This lab demonstrated classic stored XSS in plain HTML context with zero encoding — solved with a single <script>alert(1)</script> payload.

Key Takeaways:

Stored XSS is persistent (second-order) and affects multiple users.
Identify reflection context (here: direct HTML insertion).
Basic payloads work when nothing is encoded — always test simple script tags first.
Strengthened understanding of XSS persistence, impact, and remediation.


References:

PortSwigger Web Security Academy: Stored XSS into HTML context with nothing encoded
General: Stored cross-site scripting
