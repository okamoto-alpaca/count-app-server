const jwt = require('jsonwebtoken');
require('dotenv').config(); // ---【追加】dotenvを読み込む

// ---【変更点】秘密鍵を環境変数から取得
const JWT_SECRET = process.env.JWT_SECRET;

const protect = (req, res, next) => {
    let token;
    if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
        try {
            token = req.headers.authorization.split(' ')[1];
            const decoded = jwt.verify(token, JWT_SECRET);
            req.user = decoded;
            next();
        } catch (error) {
            console.error('トークン認証エラー:', error);
            res.status(401).json({ message: '認証に失敗しました。トークンが無効です。' });
        }
    }
    if (!token) {
        res.status(401).json({ message: '認証に失敗しました。トークンがありません。' });
    }
};

const checkRole = (roles) => {
    return (req, res, next) => {
        if (!roles.includes(req.user.role)) {
            return res.status(403).json({ message: 'この操作を実行する権限がありません。' });
        }
        next();
    };
};

module.exports = { protect, checkRole };