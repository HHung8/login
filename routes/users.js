var express = require('express');
var router = express.Router();
const userController = require("../controllers/user.controller");

/* GET users listing. */
router.get('/', userController.index);
router.get('/login', userController.login);
router.post('/login', userController.handleLogin);
router.get('/register', userController.register);
router.post('/register', userController.handleRegister);
router.post('/logout', (req, res) => {
    // Thực hiện các bước đăng xuất, ví dụ: xóa phiên làm việc
    req.session.destroy((err) => {
      if (err) {
        console.error('Đã có lỗi xảy ra trong quá trình đăng xuất:', err);
      } else {
        res.redirect('/users');
      }
    });
  });
module.exports = router;

