const express = require('express');
const { getFirestore } = require('firebase-admin/firestore');
const { protect, checkRole } = require('../authMiddleware');

const router = express.Router();

const presetRoutes = (db) => {
    // Create Preset (POST /api/presets)
    router.post(
        '/',
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

    // Get All Presets (GET /api/presets)
    router.get(
        '/',
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

    // Delete Presets (DELETE /api/presets)
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

    // Update Preset (PUT /api/presets/:id)
    router.put(
        '/:id',
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

    return router;
};

module.exports = presetRoutes;