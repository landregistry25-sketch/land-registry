import pymysql
from werkzeug.security import generate_password_hash

# 🧠 Edit your DB credentials here
MYSQL_USER = "root"
MYSQL_PASSWORD = "Harish05"
MYSQL_DB = "test"
MYSQL_HOST = "localhost"


# 🧩 Create the admin credentials
username = "admin"
name = "System Administrator"
plain_password = "Admin@123"  # You can change this

# 🔐 Hash the password
hashed_password = generate_password_hash(plain_password)

# 💾 Insert into database
try:
    conn = pymysql.connect(
        host=MYSQL_HOST,
        user=MYSQL_USER,
        password=MYSQL_PASSWORD,
        database=MYSQL_DB,
        cursorclass=pymysql.cursors.DictCursor
    )
    cursor = conn.cursor()

    # Delete old admin if exists (optional)
    cursor.execute("DELETE FROM admin WHERE username=%s", (username,))

    # Insert new admin securely
    cursor.execute(
        "INSERT INTO admin (username, name, password) VALUES (%s, %s, %s)",
        (username, name, hashed_password)
    )

    conn.commit()
    print(f"✅ Admin user '{username}' created successfully with password '{plain_password}'")
except Exception as e:
    print("❌ Error:", e)
finally:
    conn.close()
