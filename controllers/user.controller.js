const model = require("../models/index");
const { User } = model;
const { string } = require("yup");
const bcrypt = require("bcrypt");

module.exports = {
  index: async (req, res) => {
    if (req.session.isLoggedIn) return res.redirect("/");
    const register = req.flash("register")[0];
    res.render("users/index", { register });
  },

  login: (req, res) => {
    if (req.session.isLoggedIn) {
      return res.redirect("/");
    }

    const loginError = req.flash("login")[0];
    const oldData = req.flash("oldData")[0];

    res.render("users/login", { loginError, oldData, req });
  },

  handleLogin: async (req, res, next) => {
    const { email, password } = req.body;
    const validationResult = await req.validate(req.body, {
      email: string()
        .required("Vui lòng nhập email!")
        .email("Email không đúng định dạng!"),
      password: string().required("Vui lòng nhập mật khẩu!"),
    });

    if (!validationResult) {
      req.flash("login", "Vui lòng kiểm tra lại thông tin đăng nhập!");
      req.flash("oldData", req.body);
      return res.redirect("/users/login");
    }

    try {
      const user = await User.findOne({ where: { email } });

      if (!user) {
        req.flash("login", "Email hoặc mật khẩu không tồn tại!");
        req.flash("oldData", req.body);
        return res.redirect("/users/login");
      }

      if (password.trim() !== user.password.trim()) {
        req.flash("login", "Mật khẩu không đúng!");
        req.flash("oldData", req.body);
        return res.redirect("/users/login");
      }

      req.session.isLoggedIn = {
        email,
        name: user.name,
      };
      return res.redirect("/");
    } catch (error) {
      console.error("Login error:", error.message);
      return next(error);
    }
  },
  register: (req, res) => {
    if (req.session.isLoggedIn) {
      return res.redirect("/");
    }
    res.render("users/register", {
      req,
    });
  },

  handleRegister: async (req, res, next) => {
    const { name, email, password } = req.body;

    const validationResult = await req.validate(req.body, {
      name: string().required("Vui lòng nhập tên!"),
      email: string()
        .required("Vui lòng nhập email!")
        .email("Email không đúng định dạng!"),
      password: string()
        .required("Vui lòng nhập mật khẩu!")
        .min(6, "Mật khẩu phải có ít nhất 6 ký tự!"),
    });

    if (!validationResult) {
      const { errors, oldData } = req;
      req.flash("register", "Vui lòng kiểm tra lại thông tin đăng ký!");
      req.flash("oldData", oldData);
      req.flash("errors", errors);
      return res.redirect("/users/register");
    }

    try {
      // Kiểm tra xem email đã tồn tại trong database chưa
      const existingUser = await User.findOne({ where: { email } });
      if (existingUser) {
        req.flash("register", "Email đã được đăng ký. Vui lòng chọn email khác.");
        req.flash("oldData", req.body);
        return res.redirect("/users/register");
      }

      // Lưu mật khẩu và tạo tài khoản với status=0
      const hashedPassword = await bcrypt.hash(password, 10);
      await User.create({ name, email, password: hashedPassword, status: 0 });

      req.flash("register", "Đăng ký thành công!");
      return res.redirect("/users");
    } catch (error) {
      console.error("Registration error:", error.message);
      return next(error);
    }
},
};
