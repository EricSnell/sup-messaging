/*---------- DEPENDENCIES ---------*/
var mongoose = require('mongoose');
var bcrypt = require('bcrypt');

/*---------- UserSchema -----------*/
var UserSchema = new mongoose.Schema({
   username: {
       type: String,
       required: true,
       unique: true
   },
   password: {
       type: String,
       required: true
   }
});

// Uses bcrypt.compare method to check the password against the stored hash. This calls the callback providing a boolean saying if the password was valid or not.
UserSchema.methods.validatePassword = function(password, callback) {
    bcrypt.compare(password, this.password, function(error, isValid) {
        if (error) {
            callback(error);
            return;
        }
        callback(null, isValid);
    });
};

var User = mongoose.model('User', UserSchema);

module.exports = User;