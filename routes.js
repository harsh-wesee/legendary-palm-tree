const express = require('express');
const router = express.Router();
const multer = require('multer');
const path = require('path');

const connection = require("./db_connection");
// const meetingController = require("./controlllers/calling_controller");

const storage = multer.diskStorage({
    destination:(req, file, cb) => {
        let folder = '';
        console.log("File type:", file.mimetype);
        if(file.mimetype.startsWith('image/'))
        {
            folder = './images';
        }
        else if(file.mimetype.startsWith('application/pdf'))
        {
            folder = './documents';
        }
        else if(file.mimetype.startsWith('audio/'))
        {
            folder = './audios';
        }
        else 
        {
            folder = './others';
        }
        console.log("Folder", folder);
        req.uploadFolder = folder;
        cb(null, path.join(__dirname, folder));
        // cb(null, folder);
    },
    filename:(req, file, cb) => {
        const ext = path.extname(file.originalname);
        console.log("extension", ext);
        cb(null, Date.now()+ ext);
    }
})

const upload = multer({
    storage: storage,
})

router.post("/addimage", upload.single("img"), (req, res) => {
    try{
        const filePath = req.file.filename;
        const folder = req.uploadFolder;
        res.json({
            path: filePath,
            // path: req.file.filename
            url: `/download/${folder}/${filePath}`
        });
    }
    catch(e)
    {
        res.status(500).json({ error: e.message });
    }
});

router.post("/adddocument", upload.single("doc"), async (req, res) => {
    try {
        const filePath = req.file.filename;
        const folder = req.uploadFolder;
        res.json({
            path: filePath,
            url: `/download/${folder}/${filePath}`
        });
    }
    catch (e)
    {
        res.status(500).json({ error: e.message });
    }
});

router.post("/addaudio", upload.single("file"), (req, res) => {
    try {
        const filePath = req.file.filename;
        const folder = req.uploadFolder;
        res.json({
            path: filePath,
            url: `/download/${folder}/${filePath}`
        });
    }
    catch (e)
    {
        res.status(500).json({ error: e.message });
    }
});

router.post("/addothers", upload.single("file"), (req, res) => {
    try {
        const filePath = req.file.filename;
        const folder = req.uploadFolder;
        res.json({
            path: filePath,
            url: `/download/${folder}/${filePath}`
        });
    }
    catch (e)
    {
        res.status(500).json({ error: e.message });
    }
});


module.exports = router;