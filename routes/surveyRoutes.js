const express = require('express');
const { getFirestore } = require('firebase-admin/firestore');
const { protect, checkRole } = require('../authMiddleware');

const router = express.Router();

const surveyRoutes = (db) => {
    // --- Survey Templates ---

    router.post(
        '/',
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

    router.get(
        '/',
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

    router.delete(
        '/',
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

    router.put(
        '/:id',
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
    
    // ---【変更点】Survey InstancesのAPIをこちらに統合 ---
    
    router.post(
        '/instances',
        protect,
        async (req, res) => {
            try {
                const { surveyTemplateId, surveyTemplateName } = req.body;
                if (!surveyTemplateId || !surveyTemplateName) {
                    return res.status(400).json({ message: '調査テンプレートの情報が不足しています。' });
                }
                const newInstance = {
                    surveyTemplateId,
                    name: surveyTemplateName,
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

    router.get(
        '/instances/in-progress',
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

    return router;
};

module.exports = surveyRoutes;