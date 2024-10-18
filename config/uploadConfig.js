import multer, { diskStorage } from 'multer';
import { extname as _extname } from 'path';
import { fileURLToPath } from 'url';
import fs from 'fs';
import { dirname, join } from 'path';

// Configurar o local de armazenamento e o nome do arquivo
const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const uploadDirectory = join(__dirname, '../uploads/');

if (!fs.existsSync(uploadDirectory)) {
    fs.mkdirSync(uploadDirectory, { recursive: true });
}

const storage = diskStorage({
    destination: function (req, file, cb) {
        cb(null, uploadDirectory); // Pasta onde as imagens serão salvas
    },
    filename: function (req, file, cb) {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        cb(null, file.fieldname + '-' + uniqueSuffix + _extname(file.originalname));
    }
});

// Filtro para aceitar apenas arquivos de imagem
const fileFilter = (req, file, cb) => {
    const allowedTypes = /jpeg|jpg|png|gif/;
    const mimeType = allowedTypes.test(file.mimetype);
    const extname = allowedTypes.test(_extname(file.originalname).toLowerCase());

    if (mimeType && extname) {
        cb(null, true);
    } else {
        cb(new Error('Only images are allowed'));
    }
};

// Limitar o tamanho do arquivo a 5MB
const upload = multer({
    storage: storage,
    fileFilter: fileFilter,
    limits: { fileSize: 5 * 1024 * 1024 } // 5MB
});

export default upload;