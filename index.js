var path = require('path'),
	fs = require('fs'),
	util = require('util'),
	moootools = require('mootools'),
	//for authentication
	flash = require('connect-flash'); //for passport flash
	//session = require('express-session');//for passport session
	
var	packageJSON = JSON.parse(fs.readFileSync(path.join(__dirname, '/package.json')));

exports.VERSION = packageJSON.version.split('.');

//exports.Memory = require('./lib/memory.js');
// var Memory = require('./lib/memory.js');
// exports.Memory = Memory;

//exports.Imap = require('./lib/imap.js');
// var Auth = require('./lib/imap.js');
// exports.Auth = Auth;


module.exports = new Class({
// module.exports =  new Class({
  Implements: [Options, Events],

  
  ON_AUTH: 'onAuth',
  
  app: null,
  passport: null,
  store: null,
  auth: null,
  
  options: {
		store: null,
		auth: null,
		passport : {
			session: true,
		}
	},
	
  initialize: function(app, options){
		
		this.setOptions(options);
		
		this.app = app;
		
		this.addEvent(this.ON_AUTH, function(obj){
			if(obj.error)
			app.log('authentication', 'warn', 'authentication : ' + util.inspect(obj));
			else
			app.log('authentication', 'info', 'authentication : ' + util.inspect(obj));
		}.bind(this));
		
		//this.store = store;

		//this.auth = auth;
		
	// 	this.store = new Memory();
	// 	this.auth = new Auth();
		
		this.passport = require('passport');
		
		// Passport session setup.
		//   To support persistent login sessions, Passport needs to be able to
		//   serialize users into and deserialize users out of the session.  Typically,
		//   this will be as simple as storing the user ID when serializing, and finding
		//   the user by ID when deserializing.
		this.passport.serializeUser(this.options.store.serialize.bind(this.options.store));

		this.passport.deserializeUser(this.options.store.deserialize.bind(this.options.store));
		
		var authenticate = function(username, password, done) {
			console.log('node-express-auth: '+ username + ' ' +password);
			// asynchronous verification, for effect...
			process.nextTick(function () {
			
				// Find the user by username.  If there is no user with the given
				// username, or the password is not correct, set the user to `false` to
				// indicate failure and set a flash message.  Otherwise, return the
				// authenticated `user`.
				this.options.auth.authenticate(username, password, function(err, user) {
					//console.log('auth.authenticate err: ');
					//console.log(err);
					//console.log('auth.authenticate user: ');
					//console.log(user);
						
					user = this.options.store.findByUserName(user);
					
					this.fireEvent(this.ON_AUTH, {error: err, username: username});
		// 			console.log('err ' +err);
		// 			console.log('auth');
		// 			if (err) { 
		// 			  return done(err);
		// 			}
					if (!user) {
			// 			  console.log('no user ' +username);
						//err.message = 'Wrong credentials';
						//return done(null, false, { error: err });
						return done(null, false, { error: err });
					}
		// 			if (user.password != password) { 
		// 			  console.log(user);
		// 			  return done(null, false, { message: 'Invalid password' }); 
		// 			}
					
		// 			console.log('user');
		// 			console.log(user);
					return done(null, user);
					
				}.bind(this))
			
			}.bind(this));
		};
		
		var LocalStrategy = require('passport-local').Strategy;
		var BasicStrategy = require('passport-http').BasicStrategy;
		
		
		this.app['authenticate'] = function(req, res, next, func){
			/**
			 * Authorization: Basic bGJ1ZW5vOjQwYmQwMDE1NjMwODVmYzM1MTY1MzI5ZWExZmY1YzVlY2JkYmJlZWY=
			 * 
			 * */
			
			if(req.headers.authorization && req.headers.authorization.indexOf('Basic') == 0){
				console.log('nod-express-auth: setting BasicStrategy');
				// Use the LocalStrategy within Passport.
				//   Strategies in passport require a `verify` function, which accept
				//   credentials (in this case, a username and password), and invoke a callback
				//   with a user object.  In the real world, this would query a database;
				//   however, in this example we are using a baked-in set of users.
				this.passport.use(new BasicStrategy(authenticate.bind(this)));
			
			
				this.passport.authenticate('basic', {session: this.options.passport.session}, func)(req, res, next);
			}
			else{
				/**
				 * Content-Type: application/json
				 * 
				 * {"username": "lbueno", "password": "40bd001563085fc35165329ea1ff5c5ecbdbbeef"}
				 * */
				console.log('nod-express-auth: setting LocalStrategy');
				// Use the LocalStrategy within Passport.
				//   Strategies in passport require a `verify` function, which accept
				//   credentials (in this case, a username and password), and invoke a callback
				//   with a user object.  In the real world, this would query a database;
				//   however, in this example we are using a baked-in set of users.
				this.passport.use(new LocalStrategy(authenticate.bind(this)));
			
				this.passport.authenticate('local', {session: this.options.passport.session}, func)(req, res, next);

			}
		}.bind(this);
		
		//implements a check_authentication function on the App, only if the App doens't implement one
		if(!this.app.check_authentication){
			console.log('no authentication method');

			this.app['check_authentication'] = function(req, res, next){
				  if (!req.isAuthenticated()) {
					
					//if(req.headers.authorization && req.headers.authorization.indexOf('Basic') == 0){
					  
					  this.app.authenticate(req, res, next,  function(err, user, info) {
						
							//console.log('authenticate err: ');
							//console.log(err);
							//console.log('authenticate user: ');
							//console.log(user);
							//console.log('authenticate info: ');
							//console.log(info);
							
							//this.app.profile('login_authenticate');
							
							if (err) {
								this.app.log('login', 'error', err);
								req.flash('error', err);
								//res.send(info);
								//return next(err)
								//res.status(500).send(err);
								////res.status(500);
								////return next();
								this.app['500'](req, res, next, err);
							}
							if (!user) {
								this.app.log('login', 'warn', 'login authenticate ' + info);
								req.flash('error', info);
								//res.send(info);
								//res.status(403).send(info);
								//return next(info.message)
								////res.status(403);
								////return next();
								
								this.app['403'](req, res, next, info);
							}
							else{
								req.logIn(user, function(err) {
									if (err) {
										this.app.log('login', 'error', err);
										req.flash('error', err);
										////res.status(500).send(err);
										//res.status(500);
										//return next();
										////res.send(info.message);
										this.app['500'](req, res, next, err);
									}
									
									console.log('error');
									console.log(err);
									
				// 					  server.log('login', 'info', 'login authenticate ' + util.inspect(user));
									
									return next();
								
								}.bind(this));
							}
						
					  }.bind(this));
					
					//}
					//else{
					  //if(req.is('application/json') || req.path.indexOf('/api') == 0){
						//server.redirect('app:api/login', req, res, next);
					  //}
					  //else{
						//server.redirect('app:login', req, res, next);
					  //}
					//}
				  }
				  else{
						console.log('authenticated');
						next();
				  }
				  
			}.bind(this);

		  
		}
		
		app.express().use(flash());//for passport 
		
		app.express().use(this.passport.initialize());
		if(this.options.passport.session === true)
			app.express().use(this.passport.session());
			
		
			
  },

});

// exports.Authentication = Authentication;

