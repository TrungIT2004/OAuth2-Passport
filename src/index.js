const express = require('express')
const passport = require('passport')
const expressSession = require('express-session')
const GoogleStrategy = require('passport-google-oauth20').Strategy
require('dotenv').config()

const app = express()

app.use(expressSession({
    secret: 'yourSecretKey', 
    resave: false,
    saveUninitialized: false,
    cookie: { secure: false, maxAge: 15 * 1000 } 
}))

app.use(express.json())
app.use(passport.initialize())
app.use(passport.session())

passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: process.env.CALLBACK_URL,
  },
  function(accessToken, refreshToken, profile, cb) {
    const user = {
      profile: {
        id: profile.id,
        displayName: profile.displayName,
        name: profile.name,
        emails: profile.emails,
        photos: profile.photos,
        accessToken,
        refreshToken,
      }
    }
    return cb(null, user)
  }
))

passport.serializeUser(function(user, cb) {
    cb(null, user)
})

passport.deserializeUser(function(obj, cb) {
    cb(null, obj)
})

// Routes
app.get('/login/google', passport.authenticate('google', {
    scope: ['profile', 'email', 'openid'],
    prompt: 'consent' 
}))

app.get('/oauth2/redirect/google',
  passport.authenticate('google', { failureRedirect: '/login', failureMessage: true }),
  function(req, res) {
    console.log(req.user.profile.photos)
    res.status(200).json(req.user) 
  }
)

app.get('/deny', (req, res) => {
  res.json('DENY')
})

app.get('/secret-data',
  (req, res) => {
    if(req.isAuthenticated()) {
      console.log(req.session.passport)
      console.log(req.sessionID)
      res.json(req.user)
    }

    res.redirect('/deny')
})

app.listen(3000, () => {
    console.log('Listening on port 3000')
})

// // Khi chưa Logged In:
// // 1. Gửi yêu cầu tới /login/google hiện lên trang đăng nhập bằng Gmail của Google.
// // 2. Đăng nhập xong sẽ gửi yêu cầu tới /oauth2/redirect/google, chạy middleware passport.authenticate trước thì sẽ chạy hàm ở trong Strategy trả về phần thông tin user.
// // 3. Thông tin user đó sẽ được tạo thành session bởi hàm passport.serializeUser() bao gồm sessionId được gửi về máy client dưới dạng cookie với tên connection.sid và một session object bao gồm thông tin user và sessionId được lưu ở session store của server.
// // 4. Tạo session xong sẽ chạy hàm trong /oauth2/redirect/google tiếp lấy req.user thông qua hàm passportport.deserializeUser()
// // 5. Có thể lấy mọi thông tin user thông qua req.user tại mọi route.
// // Ở dây không có cài đặt store cho session nên cái session data object sẽ lưu vào Menory Storage của server, thời gian hết hạn của session cookie cũng là của session data object.
// // Khi còn cookie connection.sid và thông tin session object còn trong store thì req.isAuthenticated() = true
// // Có thể dùng passport-auth0 để implement các social login