const express = require('express');
const cors = require('cors');
const admin = require('firebase-admin');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
require('dotenv').config();
const { protect, checkRole } = require('./authMiddleware');

const serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT);

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount)
});

const db = admin.firestore();
const JWT_SECRET = process.env.JWT_SECRET;

const app = express();

// ---【変更点】許可リストを本番URLに更新 ---
const allowedOrigins = [
    'http://localhost:3000', // ローカル開発環境用
    'https://count-app-frontend.vercel.app' // Vercelの本番環境用
];

const corsOptions = {
  origin: function (origin, callback) {
    if (allowedOrigins.indexOf(origin) !== -1 || !origin) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  optionsSuccessStatus: 200
};
app.use(cors(corsOptions));


app.use(express.json());

// --- 認証が不要なAPI ---
app.get('/', (req, res) => {
  res.send('APIサーバーは正常に動作しています。');
});

app.post('/api/verify-token', (req, res) => {
  const { token } = req.body;
  if (!token) {
    return res.status(401).json({ message: 'トークンがありません。' });
  }
  try {
    const decodedUser = jwt.verify(token, JWT_SECRET);
    res.status(200).json({ user: decodedUser });
  } catch (error) {
    res.status(401).json({ message: 'トークンが無効です。' });
  }
});

app.post('/api/login', async (req, res) => {
  try {
    const { companyCode, userId, password } = req.body;
    if (!companyCode || !userId || !password) {
      return res.status(400).json({ message: 'すべてのフィールドを入力してください。' });
    }
    const usersRef = db.collection('users');
    const snapshot = await usersRef
      .where('companyCode', '==', companyCode)
      .where('userId', '==', userId)
      .limit(1)
      .get();
    if (snapshot.empty) {
      return res.status(401).json({ message: 'IDまたはパスワードが違います。' });
    }
    const userDoc = snapshot.docs[0];
    const userData = userDoc.data();
    const isPasswordMatch = await bcrypt.compare(password, userData.passwordHash);
    if (!isPasswordMatch) {
      return res.status(401).json({ message: 'IDまたはパスワードが違います。' });
    }
    const userPayload = {
      id: userDoc.id,
      name: userData.name,
      role: userData.role,
      companyCode: userData.companyCode,
    };
    const token = jwt.sign(userPayload, JWT_SECRET, { expiresIn: '8h' });
    res.status(200).json({ token, user: userPayload });
  } catch (error) {
    console.error('ログイン処理中にエラーが発生しました:', error);
    res.status(500).json({ message: 'サーバー内部でエラーが発生しました。' });
  }
});

// --- 認証が必要なAPI ---
app.post(
    '/api/surveys',
    protect,
    checkRole(['master', 'super']),
    async (req, res) => {
        try {
            const { no, name, realWork, incidentalWork, wastefulWork } = req.body;
            if (!name || !name.trim()) {
                return res.status(400).json({ message: '調査名を入力してください。' });
            }
            const newSurvey = {
                no, name, realWork, incidentalWork, wastefulWork,
                createdAt: new Date(),
                authorId: req.user.id,
                companyCode: req.user.companyCode
            };
            const docRef = await db.collection('surveys').add(newSurvey);
            res.status(201).json({ message: '登録が完了しました。', id: docRef.id });
        } catch (error) {
            console.error('調査テンプレートの登録エラー:', error);
            res.status(500).json({ message: '登録中にエラーが発生しました。' });
        }
    }
);

app.get(
    '/api/surveys',
    protect,
    async (req, res) => {
        try {
            const surveysRef = db.collection('surveys');
            const snapshot = await surveysRef.where('companyCode', '==', req.user.companyCode).get();
            if (snapshot.empty) {
                return res.status(200).json([]);
            }
            const surveyList = snapshot.docs.map(doc => {
                const data = doc.data();
                return { 
                    id: doc.id, ...data,
                    createdAt: data.createdAt.toDate().toISOString()
                };
            });
            res.status(200).json(surveyList);
        } catch (error) {
            console.error('調査テンプレートの取得エラー:', error);
            res.status(500).json({ message: 'データの取得中にエラーが発生しました。' });
        }
    }
);

app.delete(
    '/api/surveys',
    protect,
    checkRole(['master', 'super']),
    async (req, res) => {
        try {
            const { ids } = req.body;
            if (!ids || !Array.isArray(ids) || ids.length === 0) {
                return res.status(400).json({ message: '削除するアイテムのIDを指定してください。' });
            }
            const batch = db.batch();
            const surveysRef = db.collection('surveys');
            ids.forEach(id => {
                const docRef = surveysRef.doc(id);
                batch.delete(docRef);
            });
            await batch.commit();
            res.status(200).json({ message: '削除が完了しました。' });
        } catch (error) {
            console.error('調査テンプレートの削除エラー:', error);
            res.status(500).json({ message: '削除中にエラーが発生しました。' });
        }
    }
);

app.post(
    '/api/results',
    protect,
    async (req, res) => {
        try {
            const resultData = req.body;
            const newResult = {
                ...resultData,
                surveyedAt: new Date(),
                surveyedBy: req.user.id,
                companyCode: req.user.companyCode
            };
            const docRef = await db.collection('results').add(newResult);
            res.status(201).json({ message: '調査結果を保存しました。', id: docRef.id });
        } catch(error) {
            console.error('調査結果の保存エラー:', error);
            res.status(500).json({ message: '結果の保存中にエラーが発生しました。' });
        }
    }
);

app.get(
    '/api/results',
    protect,
    checkRole(['master', 'super']),
    async (req, res) => {
        try {
            const { startDate, endDate } = req.query;
            if (!startDate || !endDate) {
                return res.status(400).json({ message: '開始日と終了日を指定してください。' });
            }
            let query = db.collection('results')
                .where('companyCode', '==', req.user.companyCode)
                .where('surveyedAt', '>=', new Date(startDate))
                .where('surveyedAt', '<=', new Date(endDate));
            const snapshot = await query.get();
            const resultsList = snapshot.docs.map(doc => {
                const data = doc.data();
                return {
                    id: doc.id, ...data,
                    surveyedAt: data.surveyedAt.toDate().toISOString()
                };
            });
            res.status(200).json(resultsList);
        } catch (error) {
            console.error('調査結果の検索エラー:', error);
            res.status(500).json({ message: '結果の検索中にエラーが発生しました。' });
        }
    }
);

const PORT = 8080;
app.listen(PORT, () => {
  console.log(`サーバーがポート ${PORT} で起動しました。`);
});