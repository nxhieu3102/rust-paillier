const express = require('express');
const app = express();
const path = require('path');
const cors = require('cors');

app.use(cors());
app.use('/gmp.wasm', express.static(path.join(__dirname, 'gmp.wasm')));

app.listen(8081, () => {
  console.log('Server is running on http://localhost:8081');
});
