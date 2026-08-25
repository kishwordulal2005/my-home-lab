"""
difficulty.py — Filter/sanitizer functions for each difficulty tier.

All filter functions take (value, level) where level is 'easy', 'medium', or 'hard'.
The vulnerable routes call these before passing data to SQL queries or rendering.
"""

import re


def sanitize_sql(value, level):
    """
    SQL input filter — applied to user-supplied values before string
    concatenation into queries.

    easy:   No filtering at all.
    medium: Case-sensitive keyword blacklist. Bypassable via case variation
            or inline comments.
    hard:   Regex-based keyword filter, case-sensitive, whitespace-sensitive.
            Deliberately beaten by inline comments, case mix, operator equivs,
            and MySQL versioned comment syntax (simulated).
    """
    if level == "easy":
        return value

    if level == "medium":
        # Simple case-sensitive blacklist of common SQL keywords
        blocked = ["union", "select", "or ", "or\t", "or\n",
                    "--", "#", "drop", "delete", "insert", "update"]
        result = value
        for word in blocked:
            # Replace only exact case-sensitive matches
            result = result.replace(word, "")
        return result

    if level == "hard":
        # Regex-based, case-sensitive, whitespace-sensitive filter
        # Only matches keywords when surrounded by spaces (or at string edges)
        # This is deliberately naive — beaten by inline comments, case mix, etc.

        # FIRST: Simulate MySQL versioned comment unwrapping.
        # Real MySQL executes code inside /*! ... */ if the version number
        # matches. Our naive filter just sees a "comment" and ignores what's
        # inside — so the keyword slips past. We simulate this by stripping
        # the /*!...*/ wrapper BEFORE the filter runs, revealing the keyword.
        result = re.sub(r'/\*![0-9]*(.*?)\*/', r'\1', value)

        patterns = [
            r'(\s|^)union(\s|$)',
            r'(\s|^)select(\s|$)',
            r'(\s|^)or(\s|$)',
            r'(\s|^)and(\s|$)',
            r'--\s',
        ]
        for pat in patterns:
            result = re.sub(pat, ' ', result)
        return result

    return value


def filter_xss(value, level):
    """
    XSS filter — always returns raw value.

    Every payload (<script>, <img onerror>, <svg onload>) works at ALL
    difficulty levels so sqlmap / ghauri / Burp Repeater payloads fire
    regardless of tier.  Kept as a no-op so difficulty plumbing stays
    visible in the code.
    """
    return value


def check_upload(filename, level):
    """
    File upload validation. Returns (allowed: bool, reason: str).

    easy:   Always allow.
    medium: Blocklist of dangerous extensions (case-sensitive check).
    hard:   Naive last-extension-only check — blocks direct .php but
            allows shell.php.jpg because it only inspects the final extension.
    """
    if level == "easy":
        return True, ""

    # Get the LAST extension (what a naive check looks at)
    ext = filename.rsplit('.', 1)[-1].lower() if '.' in filename else ''

    if level == "medium":
        # Case-sensitive blocklist check
        raw_ext = filename.rsplit('.', 1)[-1] if '.' in filename else ''
        dangerous = ['php', 'py', 'sh', 'exe', 'bat', 'cmd', 'ps1',
                     'js', 'jsp', 'asp', 'aspx', 'cgi', 'pl']
        # Check the raw extension (case-sensitive) — bypassable via .PHP
        if raw_ext in dangerous:
            return False, f"Extension '.{raw_ext}' is not allowed."
        return True, ""

    if level == "hard":
        # Naive "last extension only" allowlist — the key flaw:
        # This only checks the FINAL extension, so shell.php.jpg passes
        # because the last extension is .jpg (allowed).
        # A real app would check ALL extensions or use a proper allowlist.
        allowed_last = ['jpg', 'jpeg', 'png', 'gif', 'webp', 'txt', 'csv', 'pdf']
        if ext not in allowed_last:
            return False, f"Last extension '.{ext}' not in allowed list."
        # NOTE: We deliberately do NOT check for dangerous middle extensions.
        # shell.php.jpg passes because .jpg is the last extension.
        # The file is saved with its full original name to disk.
        return True, ""

    return True, ""


def filter_dom_xss(value, level):
    """DOM sanitizer — no-op at every tier.  Client-side innerHTML / write always fires."""
    return value


def idor_requires_login(level):
    """Return True if /profile?id= requires a login session at this tier."""
    # Easy: no login required at all (fully anonymous IDOR)
    # Medium: login required but no ownership check
    # Hard: login required, UUID-based IDs, no ownership check
    return level in ("medium", "hard")


def idor_uses_uuid(level):
    """Return True if /profile?id= uses UUIDs instead of sequential integer IDs."""
    return level == "hard"
