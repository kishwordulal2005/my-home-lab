"""
mysql_sim.py — Simulate MySQL-specific SQLi behaviors on top of SQLite.

This module makes the vulnerable lab behave like a MySQL server for SQLi
training purposes:
- Different column counts per product ID (confuses UNION-based SQLi)
- GROUP BY RAND() "Duplicate entry" error simulation
- EXTRACTVALUE/XPath error-based extraction simulation
- MySQL-formatted error messages
"""

import re
import sqlite3
from seed import DB_PATH

# Simulated MySQL version string (appears in error-based extractions)
MYSQL_VERSION = "8.0.35-0ubuntu0.22.04.1"
MYSQL_USER = "root@localhost"
MYSQL_DB = "vulnlab"

# --- Column-count configuration per product ID ---
# Different product IDs use different SELECT projections,
# so UNION-based SQLi column counts keep changing.
#
# 1-5  -> 7 columns (SELECT id,name,description,price,category_id,NULL,NULL)
# 6    -> 4 columns (SELECT id,name,price,category_id)                  (UNION fails!)
# 7-8  -> 7 columns (same as 1-5)
# 9-10 -> 5 columns (SELECT id,name,description,price,category_id)     (UNION fails!)
# >10  -> 5 columns: default


def get_product_col_config(product_id):
    """Return (col_count, config_label) for a given product ID.
    Extracts the leading integer even from SQLi payloads."""
    m = re.match(r'(\d+)', str(product_id))
    if m:
        pid = int(m.group(1))
    else:
        return 5, "default"

    if 1 <= pid <= 5:
        return 7, "padded"
    elif pid == 6:
        return 4, "few"
    elif 7 <= pid <= 8:
        return 7, "padded"
    elif 9 <= pid <= 10:
        return 5, "natural"
    else:
        return 5, "default"


def build_product_select(product_id):
    """
    Build a SELECT query with a column count that varies by product ID.
    Returns (query_string, col_count).
    """
    col_count, config = get_product_col_config(product_id)

    if config == "few":
        # 4 columns — tricks UNION hunters (fewer than expected)
        query = (
            f"SELECT id, name, price, category_id "
            f"FROM products WHERE id = '{product_id}'"
        )
    elif config == "padded":
        # 7 columns — padded with extra NULLs (more than expected)
        query = (
            f"SELECT id, name, description, price, category_id, "
            f"NULL as extra1, NULL as extra2 "
            f"FROM products WHERE id = '{product_id}'"
        )
    else:
        # 5 columns — the "natural" view
        query = (
            f"SELECT id, name, description, price, category_id "
            f"FROM products WHERE id = '{product_id}'"
        )

    return query, col_count


# --- MySQL error simulation ---


def _mysql_to_sqlite(sql):
    """
    Convert a MySQL-flavoured SELECT into an equivalent SQLite statement.
    Handles: VERSION(), DATABASE(), USER(), hex literals (0x??),
             CONCAT_WS / CONCAT -> ||, FLOOR/RAND -> literal approximations.
    """
    q = sql

    # VERSION() -> literal string
    q = re.sub(r"VERSION\s*\(\s*\)", f"'{MYSQL_VERSION}'", q, flags=re.I)
    # DATABASE() -> literal
    q = re.sub(r"DATABASE\s*\(\s*\)", f"'{MYSQL_DB}'", q, flags=re.I)
    # USER() -> literal
    q = re.sub(r"USER\s*\(\s*\)", f"'{MYSQL_USER}'", q, flags=re.I)

    # Hex literals 0x0a -> character
    def _hex_replace(m):
        try:
            return "'" + bytes.fromhex(m.group(1)).decode("utf-8", errors="replace") + "'"
        except Exception:
            return m.group(0)
    q = re.sub(r"0x([0-9a-fA-F]+)", _hex_replace, q)

    # FLOOR(RAND(n)*k) -> literal 0 (approximation for GROUP BY trick)
    q = re.sub(r"FLOOR\s*\(\s*RAND\s*\([^)]*\)\s*\*\s*\d+\s*\)", "0", q, flags=re.I)
    q = re.sub(r"FLOOR\s*\(\s*RAND\s*\(\s*\)\s*\*\s*\d+\s*\)", "0", q, flags=re.I)
    q = re.sub(r"RAND\s*\(\s*\d*\s*\)", "0", q, flags=re.I)

    # CONCAT_WS(sep, a, b, ...) -> a || sep || b || sep || ...
    def _concat_ws_replace(m):
        parts = _split_args(m.group(1))
        if len(parts) < 2:
            return m.group(0)
        sep = parts[0].strip()
        values = [p.strip() for p in parts[1:]]
        result = values[0]
        for v in values[1:]:
            result += f" || {sep} || {v}"
        return result
    q = re.sub(r"(?<!\w)CONCAT_WS\s*\((.+)\)", _concat_ws_replace, q, flags=re.I)

    # CONCAT(a, b, ...) -> a || b || ...
    def _concat_replace(m):
        parts = _split_args(m.group(1))
        return " || ".join(p.strip() for p in parts)
    q = re.sub(r"(?<!\w)CONCAT\s*\((.+)\)", _concat_replace, q, flags=re.I)

    return q


def _split_args(s):
    """Split a comma-separated argument list, respecting parentheses."""
    depth = 0
    current = []
    parts = []
    for ch in s:
        if ch == "(":
            depth += 1
            current.append(ch)
        elif ch == ")":
            depth -= 1
            current.append(ch)
        elif ch == "," and depth == 0:
            parts.append("".join(current))
            current = []
        else:
            current.append(ch)
    if current:
        parts.append("".join(current))
    return parts


def _extract_inner_select(raw):
    """
    Extract the inner SELECT from an EXTRACTVALUE / UPDATEXML payload.
    Uses balanced-paren matching instead of fragile regex.

    Patterns handled:
      extractvalue(..., concat(..., (select ...)))
      updatexml(..., concat(..., (select ...)))
      extractvalue(..., (select ...))

    Returns the SELECT string or None.
    """
    # Must contain extractvalue or updatexml
    if not re.search(r'(?:extractvalue|updatexml)', raw, re.I):
        return None

    # Find the opening ( before SELECT using regex
    select_open = re.search(r'\(\s*(SELECT\s+)', raw, re.I)
    if not select_open:
        return None

    # Balanced-paren walk starting from that opening (
    start = select_open.start()
    depth = 0
    for i in range(start, len(raw)):
        if raw[i] == '(':
            depth += 1
        elif raw[i] == ')':
            depth -= 1
            if depth == 0:
                inner = raw[start + 1:i].strip()
                return inner

    return None


def _extract_group_by_payload(raw):
    """
    Detect a GROUP BY ... HAVING ... payload (MySQL error-based trick).
    Returns a simulated version string if detected, else None.

    The trick causes MySQL to throw "Duplicate entry '<version>:1' for key ..."
    """
    if re.search(r"GROUP\s+BY", raw, re.I) and re.search(r"HAVING", raw, re.I):
        return MYSQL_VERSION
    return None


def simulate_mysql_error(sqlite_error, raw_input, db=None):
    """
    Given a SQLite error and the raw user input, return a MySQL-style
    error string.  Returns None if no simulation applies (caller should
    fall back to normal error handling).
    """
    err_lower = sqlite_error.lower()

    # --- 1. EXTRACTVALUE / XPath error-based extraction ---
    inner = _extract_inner_select(raw_input)
    if inner:
        sqlite_select = _mysql_to_sqlite(inner)
        if db is None:
            db_conn = sqlite3.connect(DB_PATH)
            db_conn.row_factory = sqlite3.Row
            should_close = True
        else:
            db_conn = db
            should_close = False
        try:
            row = db_conn.execute(sqlite_select).fetchone()
            if row:
                extracted = str(row[0])
            else:
                extracted = ""
        except Exception:
            extracted = ""
        finally:
            if should_close:
                db_conn.close()
        # MySQL XPATH syntax error format — leaks the extracted data
        return f"XPATH syntax error: '\\n{extracted}'"

    # --- 2. GROUP BY RAND() Duplicate Entry ---
    version = _extract_group_by_payload(raw_input)
    if version:
        return f"Duplicate entry '{version}:1' for key 'group_key'"

    # --- 3. Column-count mismatch (UNION with wrong columns) ---
    if "different number" in err_lower or "selects to the left and right" in err_lower:
        return "The used SELECT statements have a different number of columns"

    # No simulation matched
    return None
