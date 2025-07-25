const express = require('express');
const multer = require('multer');
const clamav = require('clamav.js');
const fs = require('fs');

const app = express();
const upload = multer({ dest: 'uploads/' });

app.post('/scan', upload.single('file'), (req, res) => {
  const filePath = req.file.path;
  const stream = fs.createReadStream(filePath);

  clamav.ping(3310, 'localhost', 1000, function(err) {
    if (err) {
      return res.json({ status: 'error', message: 'ClamAV not running or unreachable.' });
    }

    clamav.createScanner(3310, 'localhost').scan(stream, function(err, object, malicious) {
      fs.unlink(filePath, () => {}); // Clean up uploaded file

      if (err) {
        res.json({ status: 'error', message: err.message });
      } else if (malicious) {
        res.json({ status: 'infected', virus: object });
      } else {
        res.json({ status: 'clean' });
      }
    });
  });
});

app.listen(3000, () => console.log('Server running on http://localhost:3000'));
