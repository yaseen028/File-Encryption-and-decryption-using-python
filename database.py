import sqlite3
import bcrypt

def init_db():
    conn = sqlite3.connect('app.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY,
                    username TEXT UNIQUE,
                    email TEXT UNIQUE,
                    password_hash TEXT)''')

    c.execute('''CREATE TABLE IF NOT EXISTS files (
                    id INTEGER PRIMARY KEY,
                    user_id INTEGER,
                    filename TEXT,
                    encrypted_data TEXT,
                    is_decrypted INTEGER DEFAULT 0,
                    FOREIGN KEY(user_id) REFERENCES users(id))''')
    conn.commit()
    conn.close()

def register_user(username, email, password):
    conn = sqlite3.connect('app.db')
    c = conn.cursor()
    password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
    try:
        c.execute('INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)', 
                  (username, email, password_hash))
        conn.commit()
    except sqlite3.IntegrityError:
        return False
    conn.close()
    return True

def authenticate_user(username, password):
    conn = sqlite3.connect('app.db')
    c = conn.cursor()
    c.execute('SELECT id, password_hash FROM users WHERE username = ?', (username,))
    user = c.fetchone()
    conn.close()
    if user and bcrypt.checkpw(password.encode(), user[1]):
        return user[0]
    return None

def store_file(user_id, filename, encrypted_data):
    conn = sqlite3.connect('app.db')
    c = conn.cursor()
    c.execute('INSERT INTO files (user_id, filename, encrypted_data) VALUES (?, ?, ?)', 
              (user_id, filename, encrypted_data))
    conn.commit()
    conn.close()

def get_user_files(user_id, is_decrypted):
    conn = sqlite3.connect('app.db')
    c = conn.cursor()
    c.execute('SELECT id, filename, encrypted_data FROM files WHERE user_id = ? AND is_decrypted = ?',
              (user_id, is_decrypted))
    files = c.fetchall()
    conn.close()
    return files

def mark_file_as_decrypted(file_id):
    conn = sqlite3.connect('app.db')
    c = conn.cursor()
    c.execute('UPDATE files SET is_decrypted = 1 WHERE id = ?', (file_id,))
    conn.commit()
    conn.close()
