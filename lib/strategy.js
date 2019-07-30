
var util = require('util'),
    OAuth2Strategy = require('passport-oauth2'),
    InternalOAuthError = require('passport-oauth2').InternalOAuthError;

var DEFAULT_CLIENT_SECRET = 'kakao';

/**
 * KaKaoStrategy 생성자.<br/>
 * @param options.clientID 필수. kakao rest app key.
 * @param options.callbackURL 필수. 로그인 처리 후 호출할 URL
 * @param verify
 * @constructor
 */
function Strategy(options, verify) {
    var oauthHost = 'https://kauth.kakao.com';
    options = options || {};
    options.authorizationURL = oauthHost + '/oauth/authorize';
    options.tokenURL = oauthHost + '/oauth/token';

    if (!options.clientSecret) {
        options.clientSecret = DEFAULT_CLIENT_SECRET;
    }

    options.scopeSeparator = options.scopeSeparator || ',';
    options.customHeaders = options.customHeaders || {};

    if (!options.customHeaders['User-Agent']) {
        options.customHeaders['User-Agent'] = options.userAgent || 'passport-kakao';
    }

    OAuth2Strategy.call(this, options, verify);
    this.name = 'kakao-token';
    this._userProfileURL = 'https://kapi.kakao.com/v2/user/me';
    this._accessTokenField = options.accessTokenField || 'access_token';
    this._refreshTokenField = options.refreshTokenField || 'refresh_token';
    this._passReqToCallback = options.passReqToCallback || false;

    // client secret이 파라메터에 있으면 엑세스 토큰 조회시 에러가 나므로 생성에서만 쓰고 생성 후엔 삭제한다.
    delete this._oauth2._clientSecret;
}

/**
 * `OAuth2Stragegy`를 상속 받는다.
 */
util.inherits(Strategy, OAuth2Strategy);


/**
 * Authenticate request by delegating to a service provider using OAuth 2.0.
 * It's only allows GET parameters `access_token` as query property in the connect middleware.
 */
Strategy.prototype.authenticate = function (req, options) {
    var accessToken = req.query[this._accessTokenField];
    var refreshToken = req.query[this._refreshTokenField];
    var self = this;

    if (!accessToken) return this.fail({message: 'You should provide ${this._accessTokenField}'});

    this._loadUserProfile(accessToken, function (error, profile) {
        if (error) {
            return self.error(error);
        }

        var verified = function (error, user, info) {
            if (error) {
                return self.error(error);
            }

            if (!user) {
                return self.fail(info);
            }

            return self.success(user, info);
        };

        if (self._passReqToCallback) {
            self._verify(req, accessToken, refreshToken, profile, verified);
        } else {
            self._verify(accessToken, refreshToken, profile, verified);
        }
    });
};

/**
 * kakao 사용자 정보를 얻는다.<br/>
 * 사용자 정보를 성공적으로 조회하면 아래의 object가 done 콜백함수 호출과 함꼐 넘어간다.
 *
 *   - `provider`         kakao 고정
 *   - `id`               kakao user id number
 *   - `username`         사용자의 kakao nickname
 *   - `_raw`             json string 원문
 *   _ `_json`            json 원 데이터
 *
 * @param {String} accessToken
 * @param {Function} done
 */
Strategy.prototype.userProfile = function(accessToken, done) {
    this._oauth2.get(this._userProfileURL, accessToken, function (err, body, res) {
        if (err) {
            var  errObj = JSON.parse(err.data);
            return done(new InternalOAuthError(errObj.msg, err));
        }

        try {
            var json = JSON.parse(body);
            var properties;

            var profile = { provider: 'kakao' };
            profile.id = json.id;
            // 카카오톡이나 카카오스토리에 연동한적이 없는 계정의 경우 properties가 없음
            properties = json.properties || {
                nickname: ''
            };
            profile.username = properties.nickname;
            profile.displayName = properties.nickname;

            const account = json.kakao_account;
            profile.email = account.has_email ? account.email : null;

            profile._raw = body;
            profile._json = json;

            done(null, profile);
        } catch(e) {
            done(e);
        }
    });
}


/**
 * Expose `Strategy`.
 */
module.exports = Strategy;
