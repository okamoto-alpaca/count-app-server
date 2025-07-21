const express = require('express');
const bcrypt = require('bcrypt');
const { getFirestore } = require('firebase-admin/firestore');
const { protect, checkRole } = require('../authMiddleware');

const router = express.Router();

const userRoutes = (db) => {
    // ユーザー一覧を取得 (GET /api/users)
    router.get(
        '/',
        protect,
        checkRole(['master', 'super']),
        async (req, res) => {
            try {
                let query = db.collection('users');
                // superユーザーは全ユーザー、masterは自社のユーザーのみ取得
                if (req.user.role !== 'super') {
                    query = query.where('companyCode', '==', req.user.companyCode);
                }
                const snapshot = await query.get();
                
                const userList = snapshot.docs.map(doc => {
                    const { passwordHash, ...userData } = doc.data();
                    return { id: doc.id, ...userData };
                });

                res.status(200).json(userList);
            } catch (error) {
                console.error('ユーザー一覧の取得エラー:', error);
                res.status(500).json({ message: 'ユーザー一覧の取得中にエラーが発生しました。' });
            }
        }
    );

    // 新規ユーザーを作成 (POST /api/users)
    router.post(
        '/',
        protect,
        checkRole(['master', 'super']),
        async (req, res) => {
            try {
                const { name, userId, password, role, companyCode } = req.body; // ---【変更点】companyCodeを受け取る
                
                if (!name || !userId || !password || !role) {
                    return res.status(400).json({ message: '必須フィールドが不足しています。' });
                }

                // ---【変更点】superユーザーのみcompanyCodeを指定可能 ---
                let finalCompanyCode = req.user.companyCode;
                if (req.user.role === 'super') {
                    if (!companyCode) {
                        return res.status(400).json({ message: 'superユーザーは企業コードを指定する必要があります。' });
                    }
                    finalCompanyCode = companyCode;
                }

                const salt = await bcrypt.genSalt(10);
                const passwordHash = await bcrypt.hash(password, salt);

                const newUser = {
                    name,
                    userId,
                    passwordHash,
                    role,
                    companyCode: finalCompanyCode,
                    createdAt: new Date(),
                };

                const docRef = await db.collection('users').add(newUser);
                res.status(201).json({ message: 'ユーザーを作成しました。', id: docRef.id });

            } catch (error) {
                console.error('ユーザー作成エラー:', error);
                res.status(500).json({ message: 'ユーザー作成中にエラーが発生しました。' });
            }
        }
    );

    // ユーザー情報を更新 (PUT /api/users/:id)
    router.put(
        '/:id',
        protect,
        checkRole(['master', 'super']),
        async (req, res) => {
            try {
                const { id } = req.params;
                const { name, userId, password, role, companyCode } = req.body; // ---【変更点】companyCodeを受け取る

                const updateData = { name, userId, role };

                // ---【変更点】superユーザーはcompanyCodeも更新可能 ---
                if (req.user.role === 'super' && companyCode) {
                    updateData.companyCode = companyCode;
                }

                if (password) {
                    const salt = await bcrypt.genSalt(10);
                    updateData.passwordHash = await bcrypt.hash(password, salt);
                }

                const userRef = db.collection('users').doc(id);
                await userRef.update(updateData);

                res.status(200).json({ message: 'ユーザー情報を更新しました。' });

            } catch (error) {
                console.error('ユーザー更新エラー:', error);
                res.status(500).json({ message: 'ユーザー更新中にエラーが発生しました。' });
            }
        }
    );

    // ユーザーを削除 (DELETE /api/users)
    router.delete(
        '/',
        protect,
        checkRole(['master', 'super']),
        async (req, res) => {
            try {
                const { ids } = req.body;
                if (!ids || !Array.isArray(ids) || ids.length === 0) {
                    return res.status(400).json({ message: '削除するユーザーIDを指定してください。' });
                }

                if (ids.includes(req.user.id)) {
                    return res.status(403).json({ message: '自分自身を削除することはできません。' });
                }
                
                const batch = db.batch();
                const usersRef = db.collection('users');
                ids.forEach(id => {
                    batch.delete(usersRef.doc(id));
                });
                await batch.commit();

                res.status(200).json({ message: 'ユーザーを削除しました。' });

            } catch (error)
            {
                console.error('ユーザー削除エラー:', error);
                res.status(500).json({ message: 'ユーザー削除中にエラーが発生しました。' });
            }
        }
    );

    return router;
};

module.exports = userRoutes;