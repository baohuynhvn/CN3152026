var express = require("express");
var router = express.Router();
let userController = require("../controllers/users");
let { RegisterValidator, validatedResult } = require("../utils/validator");
let { CheckLogin } = require("../utils/authHandler");
//login
router.post("/login", async function (req, res, next) {
  let { username, password } = req.body;
  let result = await userController.QueryLogin(username, password);
  if (!result) {
    res.status(404).send("thong tin dang nhap khong dung");
  } else {
    res.send(result);
  }
});
router.post(
  "/register",
  RegisterValidator,
  validatedResult,
  async function (req, res, next) {
    let { username, password, email } = req.body;
    let newUser = await userController.CreateAnUser(
      username,
      password,
      email,
      "69b6231b3de61addb401ea26",
    );
    res.send(newUser);
  },
);
router.get("/me", CheckLogin, function (req, res, next) {
  res.send(req.user);
});
router.post("/changepassword", CheckLogin, async function (req, res, next) {
  try {
    let { oldpassword, newpassword } = req.body;

    const bcrypt = require("bcrypt");

    // validate new password
    if (!newpassword || newpassword.length < 6) {
      return res.status(400).send("newpassword phai >= 6 ky tu");
    }

    let user = req.user;

    if (!user) {
      return res.status(401).send("ban chua dang nhap");
    }

    // check old password
    if (!bcrypt.compareSync(oldpassword, user.password)) {
      return res.status(400).send("old password khong dung");
    }

    // hash new password
    let hash = bcrypt.hashSync(newpassword, 10);

    const userModel = require("../schemas/users");

    await userModel.findByIdAndUpdate(
      user._id,
      { password: hash },
      { new: true },
    );

    res.send("doi mat khau thanh cong");
  } catch (error) {
    next(error);
  }
});
//register
//changepassword
//me
//forgotpassword
//permission
module.exports = router;
