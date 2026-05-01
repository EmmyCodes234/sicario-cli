// VULNERABLE: file-upload-no-mime-check — multer without fileFilter MIME validation
// Rule: FileUploadNoMimeCheck | CWE-434 | Severity: HIGH

const express = require('express');
const multer = require('multer');

const app = express();

// VULNERABLE: no fileFilter — any file type including .php, .exe, .sh is accepted
const upload = multer({ dest: 'uploads/' });

app.post('/upload', upload.single('file'), (req, res) => {
  res.json({ filename: req.file.filename, originalname: req.file.originalname });
});

app.listen(3000);
