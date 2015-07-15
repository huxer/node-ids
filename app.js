var http = require('http');
var querystring = require('querystring');
var crypto = require('crypto');
var express = require('express');
var path = require('path');
var bodyParser = require('body-parser');
var cookieParser = require('cookie-parser');
var session = require('express-session');
var port = process.env.PORT || 3000;
var app = express();

app.set('views','./views');
app.set('view engine','jade');
app.use(bodyParser.urlencoded({extended: true}));
app.use(cookieParser());
app.use(session({
	secret: 'node ids',
	resave: false,
	saveUninitialized: false
}));
app.use(express.static(path.join(__dirname, 'public')));
app.listen(port);
console.log('Server started on port '+ port);

app.use(function(req, res, next) {
	var _user = req.session.user
	app.locals.user = _user
	next()
})

app.get('/', function(req, res){
	var token = req.query['com.trs.idm.gSessionId'];
	var action = req.query.action;
	console.log('Action -> ' + action);
	if(action == 'synclogin') {
		token = req.query.trsidssdssotoken.split('_')[0];
	} else if(action == 'synclogout') {
		delete req.session.user;
		res.clearCookie('idstoken', { path: '/' });
		res.redirect('/');
		return;
	}
	if(!token) {
		token = req.cookies.idstoken;
	}
	console.log('Token -> ' + token);
	if(req.session.user) {
		res.render('index');
	} else {
		var coAppName = 'node-demo';
		var coSessionId = req.sessionID;
		var surl = 'http://localhost:3000/';
		var idsUrl = 'http://127.0.0.1:9000/ids/LoginServlet?coAppName='
			+ new Buffer(coAppName).toString('base64')
			+ '&coSessionId=' + new Buffer(coSessionId).toString('base64')
			+ '&surl=' + new Buffer(surl).toString('base64');
		if(typeof token == 'undefined') {
			console.log('Redirect to IDS...');
			res.redirect(idsUrl);
		} else {
			res.cookie('idstoken', token, { httpOnly:true, path:'/' });
			var data = querystring.stringify({
				'ssoSessionId' : token,
				'coSessionId' : coSessionId
			});
			console.log('InitData -> ' + data);
			var digest = crypto.createHash('md5').update(data, 'utf8').digest('hex');
			console.log('DigestData -> ' + digest);
			var base64Enc = new Buffer(data).toString('base64');
			var cipher = crypto.createCipheriv('des-ecb', new Buffer('12345678'), new Buffer(0));
			cipher.setAutoPadding(true);
			var desEnc = cipher.update(base64Enc, 'utf8', 'hex');
			desEnc += cipher.final('hex');
			console.log('DesEncData -> ' + desEnc);
			var finalData = digest + '&' + desEnc;

			var postData = querystring.stringify({
				'coAppName' : coAppName,
				'data' : finalData,
				'type' : 'json'
			});
			var options = {
				hostname: '127.0.0.1',
				port: 9000,
				path: '/ids/service?idsServiceType=httpssoservice&serviceName=findUserBySSOID',
				method: 'POST',
				headers: {
					'Content-Type': 'application/x-www-form-urlencoded',
					'Content-Length': postData.length
				}
			};
			var httpReq = http.request(options, function(httpRes) {
				httpRes.setEncoding('utf8');
				httpRes.on('data', function(text) {
					var digestOfServer = text.split('&')[0];
					console.log('DigestOfServer -> ' + digestOfServer);
					var result = text.split('&')[1];
					var decipher = crypto.createDecipheriv('des-ecb', new Buffer('12345678'), new Buffer(0));
					decipher.setAutoPadding(true);
					var desDec = decipher.update(result, 'hex', 'utf8');
					desDec += decipher.final('utf8');
					var txt = new Buffer(desDec, 'base64').toString();
					console.log('DecryptData -> ' + txt);
					var digestOfAgent = crypto.createHash('md5').update(txt, 'utf8').digest('hex');
					console.log('DigestOfAgent -> ' + digestOfAgent);
					if(digestOfAgent != digestOfServer) {
						res.end('Illegal Request...');
					} else {
						result = JSON.parse(txt);
						var code = result.code;
						console.log('CODE= ' + code);
						if(code == '200') {
							req.session.user = result.data.user.userName;
							res.redirect('/');
						} else {
							res.redirect('http://127.0.0.1:9000/ids/admin/login.jsp?returnUrl=' + surl);
						}
					}
				});
			});

			httpReq.on('error', function(e) {
				console.log(e.message);
			});

			httpReq.write(postData);
			httpReq.end();
		}
	}
});

app.get('/logout', function(req, res){
	var data = 'coSessionId=' + req.sessionID;
	var digest = crypto.createHash('md5').update(data, 'utf8').digest('hex');
	var base64Enc = new Buffer(data).toString('base64');
	var cipher = crypto.createCipheriv('des-ecb', new Buffer('12345678'), new Buffer(0));
	cipher.setAutoPadding(true);
	var desEnc = cipher.update(base64Enc, 'utf8', 'hex');
	desEnc += cipher.final('hex');
	var finalData = digest + '&' + desEnc;

	var postData = querystring.stringify({
		'coAppName' : 'node-demo',
		'data' : finalData,
		'type' : 'json'
	});
	var options = {
		hostname: '127.0.0.1',
		port: 9000,
		path: '/ids/service?idsServiceType=httpssoservice&serviceName=logout',
		method: 'POST',
		headers: {
			'Content-Type': 'application/x-www-form-urlencoded',
			'Content-Length': postData.length
		}
	};
	var httpReq = http.request(options, function(httpRes) {
		httpRes.setEncoding('utf8');
		httpRes.on('data', function(text) {
			var digestOfServer = text.split('&')[0];
			console.log('[Logout] DigestOfServer -> ' + digestOfServer);
			var result = text.split('&')[1];
			var decipher = crypto.createDecipheriv('des-ecb', new Buffer('12345678'), new Buffer(0));
			decipher.setAutoPadding(true);
			var desDec = decipher.update(result, 'hex', 'utf8');
			desDec += decipher.final('utf8');
			var txt = new Buffer(desDec, 'base64').toString();
			console.log('[Logout] DecryptData -> ' + txt);
			var digestOfAgent = crypto.createHash('md5').update(txt, 'utf8').digest('hex');
			console.log('[Logout] DigestOfAgent -> ' + digestOfAgent);
			if(digestOfAgent != digestOfServer) {
				res.end('Illegal Request...');
			} else {
				var result = JSON.parse(txt);
				var code = result.code;
				console.log('Logout result: ' + JSON.stringify(result));
				if(code == '200') {
					delete req.session.user;
					res.clearCookie('idstoken', { path: '/' });
					res.redirect('http://localhost:3000/');
				}
			}

		});
	});

	httpReq.on('error', function(e) {
		console.log(e.message);
	});

	httpReq.write(postData);
	httpReq.end();
});