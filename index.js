const express = require('express');
const cors = require('cors');
const admin = require('firebase-admin');
const bcrypt = require('bcrypt'); // ---【修正点】---
const jwt = require('jsonwebtoken');
require('dotenv').config();
const { protect, checkRole } = require('./authMiddleware');

const userRoutes = require('./routes/userRoutes');
const surveyRoutes = require('./routes/surveyRoutes');

const serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT);

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount)
});

const db = admin.firestore();
const JWT_SECRET = process.env.JWT_SECRET;

const app = express();

const allowedOrigins = [
    'http://localhost:3000',
    'https://count-app-frontend.vercel.app'
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
app.use('/api/users', userRoutes(db));
app.use('/api/surveys', surveyRoutes(db));

// Presets
app.post(
    '/api/presets',
    protect,
    checkRole(['master', 'super']),
    async (req, res) => {
        try {
            const { name, realWork, incidentalWork, wastefulWork } = req.body;
            if (!name || !name.trim()) {
                return res.status(400).json({ message: 'プリセット名を入力してください。' });
            }
            const newPreset = {
                name, realWork, incidentalWork, wastefulWork,
                createdAt: new Date(),
                authorId: req.user.id,
                companyCode: req.user.companyCode
            };
            const docRef = await db.collection('presets').add(newPreset);
            res.status(201).json({ message: 'プリセットを登録しました。', id: docRef.id });
        } catch (error) {
            console.error('プリセットの登録エラー:', error);
            res.status(500).json({ message: 'プリセットの登録中にエラーが発生しました。' });
        }
    }
);

app.get(
    '/api/presets',
    protect,
    checkRole(['master', 'super']),
    async (req, res) => {
        try {
            const presetsRef = db.collection('presets');
            const snapshot = await presetsRef.where('companyCode', '==', req.user.companyCode).get();
            if (snapshot.empty) {
                return res.status(200).json([]);
            }
            const presetList = snapshot.docs.map(doc => ({ id: doc.id, ...doc.data() }));
            res.status(200).json(presetList);
        } catch (error) {
            console.error('プリセットの取得エラー:', error);
            res.status(500).json({ message: 'プリセットの取得中にエラーが発生しました。' });
        }
    }
);

app.delete(
    '/api/presets',
    protect,
    checkRole(['master', 'super']),
    async (req, res) => {
        try {
            const { ids } = req.body;
            if (!ids || !Array.isArray(ids) || ids.length === 0) {
                return res.status(400).json({ message: '削除するアイテムのIDを指定してください。' });
            }
            const batch = db.batch();
            const presetsRef = db.collection('presets');
            ids.forEach(id => {
                const docRef = presetsRef.doc(id);
                batch.delete(docRef);
            });
            await batch.commit();
            res.status(200).json({ message: '削除が完了しました。' });
        } catch (error) {
            console.error('プリセットの削除エラー:', error);
            res.status(500).json({ message: '削除中にエラーが発生しました。' });
        }
    }
);

app.put(
    '/api/presets/:id',
    protect,
    checkRole(['master', 'super']),
    async (req, res) => {
        try {
            const { id } = req.params;
            const { name, realWork, incidentalWork, wastefulWork } = req.body;
            if (!name || !name.trim()) {
                return res.status(400).json({ message: 'プリセット名を入力してください。' });
            }

            const presetRef = db.collection('presets').doc(id);
            await presetRef.update({
                name, realWork, incidentalWork, wastefulWork,
                updatedAt: new Date(),
            });

            res.status(200).json({ message: '更新が完了しました。', id: id });
        } catch (error) {
            console.error('プリセットの更新エラー:', error);
            res.status(500).json({ message: '更新中にエラーが発生しました。' });
        }
    }
);


// Results & Survey Instances
app.post(
    '/api/results',
    protect,
    async (req, res) => {
        try {
            const { instanceId, ...resultData } = req.body;
            if (!instanceId) {
                return res.status(400).json({ message: '調査インスタンスIDが必要です。' });
            }
            const instanceRef = db.collection('survey_instances').doc(instanceId);
            await instanceRef.update({
                status: 'completed',
                counts: resultData.counts,
                totalCount: resultData.totalCount,
                discoveryRate: resultData.discoveryRate,
                rank: resultData.rank,
                completedAt: new Date()
            });
            res.status(200).json({ message: '調査結果を保存しました。' });
        } catch(error) {
            console.error('調査結果の保存エラー:', error);
            res.status(500).json({ message: '結果の保存中にエラーが発生しました。' });
        }
    }
);

app.post(
    '/api/results/discard',
    protect,
    async (req, res) => {
        try {
            const { instanceId } = req.body;
            if (!instanceId) {
                return res.status(400).json({ message: '調査インスタンスIDが必要です。' });
            }
            const instanceRef = db.collection('survey_instances').doc(instanceId);
            await instanceRef.update({
                status: 'discarded',
                discardedAt: new Date()
            });
            res.status(200).json({ message: '調査を破棄しました。' });
        } catch (error) {
            console.error('調査の破棄エラー:', error);
            res.status(500).json({ message: '調査の破棄中にエラーが発生しました。' });
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
            let query = db.collection('survey_instances')
                .where('companyCode', '==', req.user.companyCode)
                .where('status', '==', 'completed')
                .where('startedAt', '>=', new Date(startDate))
                .where('startedAt', '<=', new Date(endDate));
            const snapshot = await query.get();
            const resultsList = snapshot.docs.map(doc => {
                const data = doc.data();
                return {
                    id: doc.id, 
                    surveyId: data.surveyTemplateId,
                    surveyName: data.name,
                    counts: data.counts,
                    surveyedAt: data.startedAt.toDate().toISOString(),
                };
            });
            res.status(200).json(resultsList);
        } catch (error) {
            console.error('調査結果の検索エラー:', error);
            res.status(500).json({ message: '結果の検索中にエラーが発生しました。' });
        }
    }
);

app.delete(
    '/api/results',
    protect,
    checkRole(['master', 'super']),
    async (req, res) => {
        try {
            const { ids } = req.body;
            if (!ids || !Array.isArray(ids) || ids.length === 0) {
                return res.status(400).json({ message: '削除するアイテムのIDを指定してください。' });
            }
            const batch = db.batch();
            const instancesRef = db.collection('survey_instances');
            ids.forEach(id => {
                batch.delete(instancesRef.doc(id));
            });
            await batch.commit();
            res.status(200).json({ message: '調査結果を削除しました。' });
        } catch (error) {
            console.error('調査結果の削除エラー:', error);
            res.status(500).json({ message: '調査結果の削除中にエラーが発生しました。' });
        }
    }
);

app.get(
    '/api/results/all',
    protect,
    checkRole(['master', 'super']),
    async (req, res) => {
        try {
            const instancesRef = db.collection('survey_instances');
            const snapshot = await instancesRef
                .where('companyCode', '==', req.user.companyCode)
                .where('status', '==', 'completed')
                .orderBy('startedAt', 'desc')
                .get();
            if (snapshot.empty) {
                return res.status(200).json([]);
            }
            const resultsList = snapshot.docs.map(doc => {
                const data = doc.data();
                return { 
                    id: doc.id, 
                    name: data.name,
                    createdAt: data.startedAt.toDate().toISOString()
                };
            });
            res.status(200).json(resultsList);
        } catch (error) {
            console.error('全調査結果の取得エラー:', error);
            res.status(500).json({ message: '全調査結果の取得中にエラーが発生しました。' });
        }
    }
);


const PORT = 8080;
app.listen(PORT, () => {
  console.log(`サーバーがポート ${PORT} で起動しました。`);
});