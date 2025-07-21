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

// Surveys
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

app.put(
    '/api/surveys/:id',
    protect,
    checkRole(['master', 'super']),
    async (req, res) => {
        try {
            const { id } = req.params;
            const { no, name, realWork, incidentalWork, wastefulWork } = req.body;
            if (!name || !name.trim()) {
                return res.status(400).json({ message: '調査名を入力してください。' });
            }
            
            const surveyRef = db.collection('surveys').doc(id);
            await surveyRef.update({
                no, name, realWork, incidentalWork, wastefulWork,
                updatedAt: new Date(),
            });

            res.status(200).json({ message: '更新が完了しました。', id: id });
        } catch (error) {
            console.error('調査テンプレートの更新エラー:', error);
            res.status(500).json({ message: '更新中にエラーが発生しました。' });
        }
    }
);

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
            res.status(500).json({ message: 'プリセットの削除中にエラーが発生しました。' });
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


// Results
app.post(
    '/api/results',
    protect,
    async (req, res) => {
        try {
            // ---【変更点】リクエストからinstanceIdを受け取る ---
            const { instanceId, ...resultData } = req.body;

            if (!instanceId) {
                return res.status(400).json({ message: '調査インスタンスIDが必要です。' });
            }

            const newResult = {
                ...resultData,
                surveyedAt: new Date(),
                surveyedBy: req.user.id,
                companyCode: req.user.companyCode
            };

            const instanceRef = db.collection('survey_instances').doc(instanceId);

            // トランザクションで、結果の保存とインスタンスの更新を同時に行う
            await db.runTransaction(async (transaction) => {
                const instanceDoc = await transaction.get(instanceRef);
                if (!instanceDoc.exists) {
                    throw new Error("調査インスタンスが見つかりません。");
                }
                // インスタンスの状態を'completed'に更新
                transaction.update(instanceRef, { status: 'completed', counts: resultData.counts });
                // 結果を新しいドキュメントとして保存
                const resultRef = db.collection('results').doc();
                transaction.set(resultRef, newResult);
            });
            
            res.status(201).json({ message: '調査結果を保存しました。' });

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
            
            // ---【変更点】集計対象を完了済みの調査インスタンスにする ---
            let query = db.collection('survey_instances')
                .where('companyCode', '==', req.user.companyCode)
                .where('status', '==', 'completed') // 完了したものだけ
                .where('startedAt', '>=', new Date(startDate))
                .where('startedAt', '<=', new Date(endDate));

            const snapshot = await query.get();
            const resultsList = snapshot.docs.map(doc => {
                const data = doc.data();
                // フロントエンドが必要とする形式にデータを整形
                return {
                    id: doc.id, 
                    surveyId: data.surveyTemplateId,
                    surveyName: data.name, // このフィールドを追加するために、インスタンス作成時にnameも保存する必要がある
                    counts: data.counts,
                    surveyedAt: data.startedAt.toDate().toISOString(), // startedAtをsurveyedAtとして扱う
                    // rankとdiscoveryRateを再計算するか、保存時にインスタンスに含める
                };
            });
            res.status(200).json(resultsList);
        } catch (error) {
            console.error('調査結果の検索エラー:', error);
            res.status(500).json({ message: '結果の検索中にエラーが発生しました。' });
        }
    }
);

// Survey Instances
app.post(
    '/api/survey-instances',
    protect,
    async (req, res) => {
        try {
            const { surveyTemplateId, surveyTemplateName } = req.body; // ---【変更点】テンプレート名も受け取る
            if (!surveyTemplateId || !surveyTemplateName) {
                return res.status(400).json({ message: '調査テンプレートの情報が不足しています。' });
            }
            
            const newInstance = {
                surveyTemplateId,
                name: surveyTemplateName, // ---【追加】
                surveyorId: req.user.id,
                companyCode: req.user.companyCode,
                status: 'in-progress',
                counts: {},
                startedAt: new Date(),
            };

            const docRef = await db.collection('survey_instances').add(newInstance);
            res.status(201).json({ message: '調査を開始しました。', instanceId: docRef.id });
        } catch (error) {
            console.error('調査インスタンスの作成エラー:', error);
            res.status(500).json({ message: '調査の開始中にエラーが発生しました。' });
        }
    }
);

app.get(
    '/api/survey-instances/in-progress',
    protect,
    async (req, res) => {
        try {
            const instancesRef = db.collection('survey_instances');
            const snapshot = await instancesRef
                .where('companyCode', '==', req.user.companyCode)
                .where('surveyorId', '==', req.user.id)
                .where('status', '==', 'in-progress')
                .orderBy('startedAt', 'desc')
                .limit(1)
                .get();
            
            if (snapshot.empty) {
                return res.status(200).json([]);
            }

            const instances = snapshot.docs.map(doc => ({ id: doc.id, ...doc.data() }));
            res.status(200).json(instances);

        } catch (error) {
            console.error('進行中の調査の取得エラー:', error);
            res.status(500).json({ message: '進行中の調査の取得中にエラーが発生しました。' });
        }
    }
);


const PORT = 8080;
app.listen(PORT, () => {
  console.log(`サーバーがポート ${PORT} で起動しました。`);
});