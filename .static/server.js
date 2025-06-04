// Simple Node.js static file server for .static/public
const express = require('express');
const path = require('path');

const app = express();
const PORT = 9999;
const PUBLIC_DIR = path.join(__dirname, 'public');

app.use(express.static(PUBLIC_DIR));

app.listen(PORT, () => {
  console.log(`Static server running at http://localhost:${PORT}`);
});
