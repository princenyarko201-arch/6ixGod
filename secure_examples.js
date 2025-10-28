#!/usr/bin/env node
// secure_examples.js
// Example of safe parameterized queries in Node.js using mysql2 (promise API).
// Install in Termux: pkg install nodejs && npm install mysql2

const mysql = require('mysql2/promise');

async function run() {
  // Example uses local MySQL — replace with your DB and credentials
  const conn = await mysql.createConnection({host: '127.0.0.1', user: 'root', database: 'test'});
  await conn.execute('CREATE TABLE IF NOT EXISTS users (id INT AUTO_INCREMENT PRIMARY KEY, username VARCHAR(100), email VARCHAR(100))');

  // Parameterized insert
  await conn.execute('INSERT INTO users (username, email) VALUES (?, ?)', ['carol', 'carol@example.org']);

  // Parameterized select
  const [rows] = await conn.execute('SELECT id, username, email FROM users WHERE username = ?', ['carol']);
  console.log(rows);

  await conn.end();
}

run().catch(err => {
  console.error('Error:', err);
});