const model = require("../models/index");
const { User } = model;
const { string, object } = require("yup");
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
  
      // Lưu mật khẩu không mã hóa và tạo tài khoản với status=0
      await User.create({ name, email, password, status: 0 });
  
      req.flash("register", "Đăng ký thành công!");
      return res.redirect("/users");
    } catch (error) {
      console.error("Registration error:", error.message);
      return next(error);
    }
  },
  
  accountSettings: (req, res) => {
    res.render("users/accountSettings", {
      user: req.session.isLoggedIn,
    });
  },

  // New function to handle account information update
  handleAccountUpdate: async (req, res, next) => {
    const { name, email } = req.body;

    const validationResult = await req.validate(req.body, {
      name: string().required("Vui lòng nhập tên!"),
      email: string()
        .required("Vui lòng nhập email!")
        .email("Email không đúng định dạng!"),
    });

    if (!validationResult) {
      const { errors, oldData } = req;
      req.flash("accountSettings", "Vui lòng kiểm tra lại thông tin cập nhật!");
      req.flash("oldData", oldData);
      req.flash("errors", errors);
      return res.redirect("/users/account-settings");
    }

    try {
      // Check if the new email is already in use by another user
      const existingUser = await User.findOne({
        where: { email, id: { [model.Sequelize.Op.not]: req.session.isLoggedIn.id } },
      });
      if (existingUser) {
        req.flash("accountSettings", "Email đã được sử dụng bởi người khác. Vui lòng chọn email khác.");
        req.flash("oldData", req.body);
        return res.redirect("/users/account-settings");
      }

      // Update user information
      await User.update({ name, email }, { where: { id: req.session.isLoggedIn.id } });

      req.session.isLoggedIn.name = name;
      req.session.isLoggedIn.email = email;

      req.flash("accountSettings", "Cập nhật thông tin thành công!");
      return res.redirect("/users/account-settings");
    } catch (error) {
      console.error("Account update error:", error.message);
      return next(error);
    }
  },

  // New function to render password change page
  changePassword: (req, res) => {
    res.render("users/changePassword");
  },

  // New function to handle password change
  handleChangePassword: async (req, res, next) => {
    const { oldPassword, newPassword, confirmNewPassword } = req.body;

    const validationResult = await req.validate(req.body, {
      oldPassword: string().required("Vui lòng nhập mật khẩu cũ!"),
      newPassword: string().required("Vui lòng nhập mật khẩu mới!").min(6, "Mật khẩu mới phải có ít nhất 6 ký tự!"),
      confirmNewPassword: string()
        .required("Vui lòng nhập lại mật khẩu mới!")
        .oneOf([newPassword], "Mật khẩu mới không khớp!"),
    });

    if (!validationResult) {
      const { errors, oldData } = req;
      req.flash("changePassword", "Vui lòng kiểm tra lại thông tin đổi mật khẩu!");
      req.flash("oldData", oldData);
      req.flash("errors", errors);
      return res.redirect("/users/change-password");
    }

    try {
      const user = await User.findOne({ where: { id: req.session.isLoggedIn.id } });

      // Check if the provided old password matches the stored hashed password
      const isPasswordValid = await bcrypt.compare(oldPassword, user.password);
      if (!isPasswordValid) {
        req.flash("changePassword", "Mật khẩu cũ không đúng!");
        req.flash("oldData", req.body);
        return res.redirect("/users/change-password");
      }

      // Update password
      const hashedNewPassword = await bcrypt.hash(newPassword, 10);
      await User.update({ password: hashedNewPassword }, { where: { id: req.session.isLoggedIn.id } });

      req.flash("changePassword", "Đổi mật khẩu thành công!");
      return res.redirect("/users/change-password");
    } catch (error) {
      console.error("Password change error:", error.message);
      return next(error);
    }
  },

  // New function to render device management page
  deviceManagement: async (req, res, next) => {
    try {
      const sessions = await Session.findAll({
        where: { userId: req.session.isLoggedIn.id },
      });

      res.render("users/deviceManagement", { sessions });
    } catch (error) {
      console.error("Device management error:", error.message);
      return next(error);
    }
  },

  // New function to handle device logout
  handleDeviceLogout: async (req, res, next) => {
    const { sessionId } = req.params;

    try {
      await Session.destroy({ where: { id: sessionId } });

      req.flash("deviceManagement", "Đã đăng xuất khỏi thiết bị!");
      return res.redirect("/users/device-management");
    } catch (error) {
      console.error("Device logout error:", error.message);
      return next(error);
    }
  },
};
