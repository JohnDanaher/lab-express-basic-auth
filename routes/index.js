const router = require("express").Router();

/* GET home page */
router.get("/", (req, res, next) => {
  if(req.session.currentUser){
    res.render("index", { loggedIn: true });
  }
  else {
    res.render("index", { loggedIn: false });
  }
});

module.exports = router;
