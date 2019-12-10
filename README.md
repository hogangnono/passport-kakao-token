# passport-kakao-token

This module provides to authenticate with an access token on connect middleware including express.js. It will be necessary to login on the Device.

It forked from [passport-kakao](https://github.com/rotoshine/passport-kakao) and refered from [passport-facebook-token](https://github.com/drudge/passport-facebook-token).

## Installation

```
$ npm install passport-kakao-token
```

## How to Use

### Configure Strategy

```
const KakaoTokenStrategy = require('passport-kakao-token');
 
passport.use(new KakaoTokenStrategy({
    clientID: KAKAO_CLIENT_ID
  }, function(accessToken, refreshToken, profile, done) {
    User.findOrCreate({kakaoId: profile.id}, function (error, user) {
      return done(error, user);
    });
  }
));
```

### Authenticate Requests

You can authenticate with calling REST API like below.
```
GET /auth/kakao/token?access_token=[ACCESS_TOKEN]
```

And you should define a routing on your connect-style codes.
```
app.get('/auth/kakao/token', passport.authenticate('kakao-token'), function (req, res) {
    if (req.user) {
        // success
    } else {
        // fail
    }
});
```