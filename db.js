const Database = require('better-sqlite3');
const path = require('path');

const dbPath = path.join(__dirname, 'users.db');
let db;

try {
  db = new Database(dbPath);
  db.pragma('journal_mode = WAL');
} catch (err) {
  console.error('Error connecting to SQLite database:', err);
}

// Initialize tables
if (db) {
  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      last_login DATETIME
    )
  `);
}

module.exports = {
  createUser: (username, email, passwordHash) => {
    const stmt = db.prepare(
      'INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)'
    );
    const info = stmt.run(username, email.toLowerCase(), passwordHash);
    return info.lastInsertRowid;
  },

  findUserByEmail: (email) => {
    const stmt = db.prepare('SELECT * FROM users WHERE email = ?');
    return stmt.get(email.toLowerCase());
  },

  findUserByUsername: (username) => {
    const stmt = db.prepare('SELECT * FROM users WHERE username = ?');
    return stmt.get(username);
  },

  findUserById: (id) => {
    const stmt = db.prepare('SELECT id, username, email, created_at, last_login FROM users WHERE id = ?');
    return stmt.get(id);
  },

  findUserByIdWithPassword: (id) => {
    const stmt = db.prepare('SELECT * FROM users WHERE id = ?');
    return stmt.get(id);
  },

  updatePassword: (id, newPasswordHash) => {
    const stmt = db.prepare('UPDATE users SET password_hash = ? WHERE id = ?');
    return stmt.run(newPasswordHash, id);
  },

  updateLastLogin: (id) => {
    const stmt = db.prepare('UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?');
    return stmt.run(id);
  },

  getAllUsersCount: () => {
    const stmt = db.prepare('SELECT COUNT(*) as count FROM users');
    return stmt.get().count;
  }
};
