const bcrypt = require('bcrypt');
const saltRounds = 10;

const passwords = ['password123', 'password456'];

passwords.forEach(password => {
    bcrypt.hash(password, saltRounds, (err, hash) => {
        if (err) throw err;
        console.log(`Contraseña: ${password} -> Hash: ${hash}`);
    });
});