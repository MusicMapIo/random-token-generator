var crypto = require('crypto');

var rtg = module.exports = {};

// Module defaults
rtg.STRONG_KEY_LEN = 32;
rtg.WEAK_KEY_LEN = 16;

rtg.generateKey = function(opts, done) {
	if (typeof opts === 'function') {
		done = opts;
		opts = {};
	}
	opts = opts || {};
	opts.len = opts.len || (opts.strong ? rtg.STRONG_KEY_LEN : rtg.WEAK_KEY_LEN);
	opts.string = typeof opts.string !== 'undefined' ? opts.string : true;
	opts.done = opts.done || done || function() {};

	var fnc = opts.strong ? rtg.generateStrongKey : rtg.generateWeakKey;
	return fnc(opts.len, opts.string, opts.retry, opts.done);
};

rtg.generateStrongKey = function(len, str, retry, done) {
	// Generate a random string
	return crypto.randomBytes(len, function(err, key) {
		if (err && retry === false) {
			return done(err);
		} else if (err) {
			return rtg.generateStrongKey(len, str, false, done);
		}
		
		done(null, str ? key.toString('hex') : key);
	});
};

rtg.generateWeakKey = function(len, str, retry, done) {
	// Generate a random string
	return crypto.pseudoRandomBytes(len, function(err, key) {
		if (err && retry === false) {
			return done(err);
		} else if (err) {
			return rtg.generateWeakKey(len, str, false, done);
		}
		
		done(null, str ? key.toString('hex') : key);
	});
};
