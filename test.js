var crypto = require('crypto');
var txt = '{"serviceName":"findUserBySSOID","code":404,"desc":"SSO会话[1D1E57B471B3089A1F1F34917F16D2B9-10.0.103.75]不存在！","errorClass":"com.trs.idm.api.v5.sso.QUserInfoBySsoIdAndCoIdProcessor"}';
var digest = crypto.createHash('md5').update(txt, 'utf8').digest('hex');
console.log(digest);