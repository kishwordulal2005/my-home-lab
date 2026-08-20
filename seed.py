"""
seed.py — Populate the SQLite database with realistic fake data.
Run standalone: python seed.py
Or import and call seed_database(db_path).
"""

import sqlite3
import os
import uuid as _uuid

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "vulnlab.db")


def seed_database(db_path=None):
    if db_path is None:
        db_path = DB_PATH

    conn = sqlite3.connect(db_path)
    c = conn.cursor()

    # Drop existing tables
    c.execute("DROP TABLE IF EXISTS uploads")
    c.execute("DROP TABLE IF EXISTS comments")
    c.execute("DROP TABLE IF EXISTS products")
    c.execute("DROP TABLE IF EXISTS categories")
    c.execute("DROP TABLE IF EXISTS users")

    # Create users table — with private fields for IDOR demonstration
    c.execute("""
        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            uuid TEXT UNIQUE NOT NULL,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            email TEXT DEFAULT '',
            phone TEXT DEFAULT '',
            address TEXT DEFAULT '',
            bio TEXT DEFAULT '',
            is_admin INTEGER DEFAULT 0
        )
    """)

    c.execute("""
        CREATE TABLE categories (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            description TEXT DEFAULT ''
        )
    """)

    c.execute("""
        CREATE TABLE products (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            description TEXT DEFAULT '',
            price REAL NOT NULL,
            category_id INTEGER,
            FOREIGN KEY (category_id) REFERENCES categories(id)
        )
    """)

    c.execute("""
        CREATE TABLE comments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            product_id INTEGER,
            content TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id),
            FOREIGN KEY (product_id) REFERENCES products(id)
        )
    """)

    c.execute("""
        CREATE TABLE uploads (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            filename TEXT NOT NULL,
            uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    """)

    # --- Users (with private fields for IDOR + deterministic UUIDs for hard tier) ---
    # UUIDs are pre-generated deterministically so hard-tier UUID-based lookup
    # is reproducible across resets. In a real app these would be random.
    users = [
        (
            "uuid-admin-0001", "admin", "admin123",
            "admin@myhomelabexample.net", "+1-555-0100",
            "1337 Security Lane, Cyber City, CA 90210",
            "<h2>Site Administrator</h2><p>Manage all the things.</p>", 1,
        ),
        (
            "uuid-alice-0002", "alice", "password1",
            "alice.johnson@email.com", "+1-555-0101",
            "42 Coffee Street, Dogtown, OR 97201",
            "Coffee lover. Dog person. Security enthusiast.", 0,
        ),
        (
            "uuid-bob-0003", "bob", "letmein",
            "bob.smith@devmail.io", "+1-555-0102",
            "888 Code Avenue, Silicon Valley, CA 94025",
            "Full-stack dev. Building cool stuff daily.", 0,
        ),
        (
            "uuid-charlie-0004", "charlie", "charlie123",
            "charlie.photos@mailbox.org", "+1-555-0103",
            "7 Lens Boulevard, Shutter City, NY 10001",
            "Photography nerd. Always carrying a camera.", 0,
        ),
        (
            "uuid-diana-0005", "diana", "diana2024",
            "diana.ux@designhub.com", "+1-555-0104",
            "21 Pixel Place, Interface Town, TX 75001",
            "UX designer with a passion for clean interfaces.", 0,
        ),
        (
            "uuid-eve-0006", "eve", "evepassword",
            "eve.pentest@redteam.net", "+1-555-0105",
            "0 Day Drive, Exploit City, WA 98101",
            "Penetration tester by day, CTF player by night.", 0,
        ),
        (
            "uuid-frank-0007", "frank", "frank99",
            "frank.hardware@hacklab.org", "+1-555-0106",
            "1337 Solder Street, Board Town, MI 48201",
            "Hardware hacker. If it has a chip, I'll crack it.", 0,
        ),
        (
            "uuid-grace-0008", "grace", "grace2025",
            "grace.data@analytics.co", "+1-555-0107",
            "314 Pi Lane, Graph Heights, CO 80201",
            "Data scientist. Numbers tell the best stories.", 0,
        ),
        (
            "uuid-henry-0009", "henry", "henry007",
            "henry.net@packetmail.com", "+1-555-0108",
            "256 Subnet Road, Router Falls, GA 30301",
            "Network engineer. Keeping the packets flowing.", 0,
        ),
        (
            "uuid-iris-0010", "iris", "iris888",
            "iris.bugbounty@vulnhub.net", "+1-555-0109",
            "999 CVE Court, Patch City, FL 33101",
            "Bug bounty hunter. CVE collector. Bug squasher.", 0,
        ),
    ]
    c.executemany(
        """INSERT INTO users
           (uuid, username, password, email, phone, address, bio, is_admin)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
        users,
    )

    # --- Categories ---
    categories = [
        ("Electronics", "Gadgets, devices, and all things tech."),
        ("Books", "Fiction, non-fiction, and technical reads."),
        ("Clothing", "Apparel for every occasion."),
        ("Home & Garden", "Everything for your living space."),
        ("Sports & Outdoors", "Gear for the active lifestyle."),
    ]
    c.executemany(
        "INSERT INTO categories (name, description) VALUES (?, ?)", categories
    )

    # --- Products ---
    products = [
        ("Wireless Bluetooth Headphones", "Premium noise-cancelling over-ear headphones with 30-hour battery life. Crystal clear audio for music, calls, and gaming.", 79.99, 1),
        ("Mechanical Keyboard RGB", "Full-size mechanical keyboard with Cherry MX Blue switches and per-key RGB lighting. USB-C connectivity.", 129.99, 1),
        ("4K Webcam Pro", "Ultra HD webcam with auto-focus, noise-cancelling microphone, and built-in ring light. Perfect for streaming.", 59.99, 1),
        ("Portable SSD 1TB", "Ultra-fast external SSD with USB 3.2 Gen 2. Read speeds up to 1050 MB/s. Rugged aluminum casing.", 89.99, 1),
        ("Smart Watch Ultra", "GPS smartwatch with heart rate monitor, SpO2 sensor, and 14-day battery. Water resistant to 50m.", 199.99, 1),
        ("The Art of Exploitation", "A comprehensive guide to computer hacking, covering programming, networking, and cryptology techniques.", 34.99, 2),
        ("Learning Python the Hard Way", "A hands-on, project-based introduction to programming. Third edition with updated Python 3 examples.", 29.99, 2),
        ("Network Security Essentials", "Essential concepts of network security including firewalls, intrusion detection, and encryption protocols.", 44.99, 2),
        ("The Hacker Playbook 3", "Practical guide to penetration testing. Red team techniques for real-world engagements.", 39.99, 2),
        ("Digital Fortress", "A gripping techno-thriller about NSA cryptography and the race to crack an unbreakable code.", 14.99, 2),
        ("Classic Denim Jacket", "Vintage-wash denim jacket with brass buttons. Relaxed fit. Available in sizes S-XXL.", 54.99, 3),
        ("Premium Cotton T-Shirt", "100% organic cotton crew neck tee. Pre-shrunk, tagless for comfort. Multiple colors available.", 24.99, 3),
        ("Running Shoes Pro", "Lightweight performance running shoes with responsive foam cushioning and breathable mesh upper.", 119.99, 3),
        ("Waterproof Hiking Boots", "Full-grain leather hiking boots with Gore-Tex lining. Vibram outsole for superior grip.", 149.99, 3),
        ("Ergonomic Desk Lamp", "Adjustable LED desk lamp with 5 brightness levels, 3 color temperatures, and USB charging port.", 39.99, 4),
        ("Indoor Herb Garden Kit", "Self-watering planter system with grow lights. Grow fresh basil, mint, and cilantro year-round.", 49.99, 4),
        ("Robot Vacuum Cleaner", "Smart robot vacuum with LiDAR navigation, 180-minute runtime, and auto-empty dock.", 299.99, 4),
        ("Insulated Water Bottle 32oz", "Double-wall vacuum insulated stainless steel. Keeps drinks cold 24h or hot 12h.", 29.99, 5),
        ("Camping Tent 4-Person", "Lightweight waterproof dome tent with rainfly. Easy setup in under 10 minutes.", 129.99, 5),
        ("Yoga Mat Premium", "Non-slip eco-friendly yoga mat with alignment lines. 6mm thick for joint protection.", 34.99, 5),
    ]
    c.executemany(
        "INSERT INTO products (name, description, price, category_id) VALUES (?, ?, ?, ?)",
        products,
    )

    # --- Comments ---
    comments = [
        (2, 1, "Amazing sound quality! Best headphones I've owned."),
        (3, 1, "Battery life is incredible. Worth every penny."),
        (4, 3, "Crystal clear video. My streams look professional now."),
        (5, 2, "The RGB is gorgeous and the switches feel great."),
        (6, 5, "Great fitness tracker. Accurate heart rate monitoring."),
        (7, 6, "This book changed how I think about security."),
        (8, 7, "Best Python resource out there for beginners."),
        (9, 8, "Required reading for anyone in network security."),
        (10, 9, "Advanced but readable. Great for real-world testing."),
        (2, 12, "Super comfortable fabric. Bought two more in different colors."),
        (3, 14, "Took these on a 10-mile hike. Feet stayed dry the whole time."),
        (5, 16, "Just set up my indoor garden. Herbs are already sprouting!"),
        (6, 17, "Covers my entire apartment on one charge. Love it."),
        (4, 18, "Perfect for the gym. No more warm water."),
        (8, 19, "Family loved the camping trip. Tent held up in heavy rain."),
    ]
    c.executemany(
        "INSERT INTO comments (user_id, product_id, content) VALUES (?, ?, ?)",
        comments,
    )

    conn.commit()
    conn.close()
    print(f"Database seeded at {db_path}")
    print(f"  - {len(users)} users (admin/admin123)")
    print(f"  - {len(categories)} categories")
    print(f"  - {len(products)} products")
    print(f"  - {len(comments)} comments")


if __name__ == "__main__":
    seed_database()
