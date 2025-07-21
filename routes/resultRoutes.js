const express = require('express');
const { getFirestore } = require('firebase-admin/firestore');
const { protect, checkRole } = require('../authMiddleware');

const router = express.Router();

const resultRoutes = (db) => {
    // Save Survey Result (POST /api/results)
    router.post(
        '/',
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

    // Discard Survey Result (POST /api/results/discard)
    router.post(
        '/discard',
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

    // Get Survey Results by Date Range (GET /api/results)
    router.get(
        '/',
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

    // Delete Survey Results (DELETE /api/results)
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

    // Get All Survey Results (GET /api/results/all)
    router.get(
        '/all',
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
    
    return router;
};

module.exports = resultRoutes;