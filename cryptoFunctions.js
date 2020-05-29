const _crypto = require('crypto');

// encrypt/decrypt functions
module.exports = {

    /**
     * Encrypts text by given key
     * @param String text to encrypt
     * @param Buffer masterkey
     * @returns String encrypted text, base64 encoded
     */
    encrypt: function (text, masterkey,AAD){
        // random initialization vector
        const iv = _crypto.randomBytes(16);

        // random salt
        const salt = _crypto.randomBytes(64);

        // derive encryption key: 32 byte key length
        // in assumption the masterkey is a cryptographic and NOT a password there is no need for
        // a large number of iterations. It may can replaced by HKDF
        // the value of 2145 is randomly chosen!
        const key = _crypto.pbkdf2Sync(masterkey, salt, 2145, 32, 'sha512');

        // AES 256 GCM Mode
        const cipher = _crypto.createCipheriv('aes-256-gcm', key, iv);

        const bufferAAD = Buffer.from(AAD)
        cipher.setAAD(bufferAAD)

        // encrypt the given text
        const encrypted = Buffer.concat([cipher.update(text, 'utf8'), cipher.final()]);

        // extract the auth tag
        const tag = cipher.getAuthTag();

        // generate output
        return [Buffer.concat([salt, iv, bufferAAD, encrypted]).toString('base64'),tag.toString('base64'),bufferAAD.toString('ascii')];
       
    },

    /**
     * Decrypts text by given key
     * @param String base64 encoded input data
     * @param Buffer masterkey
     * @returns String decrypted (original) text
     */
    decrypt: function (encdata, masterkey,tag){
        // base64 decoding
        const bData = Buffer.from(encdata, 'base64');

        // convert data to buffers
        const salt = bData.slice(0, 64);
        const iv = bData.slice(64, 80);
        const bufferAAD = bData.slice(80, 88);
        const text = bData.slice(88);

        // derive key using; 32 byte key length
        const key = _crypto.pbkdf2Sync(masterkey, salt , 2145, 32, 'sha512');

        // AES 256 GCM Mode
        const decipher = _crypto.createDecipheriv('aes-256-gcm', key, iv);
        const tagBuffer = Buffer.from(tag, 'base64');

        decipher.setAuthTag(tagBuffer);

        decipher.setAAD(bufferAAD)

        // encrypt the given text
        const decrypted = decipher.update(text, 'binary', 'utf8') + decipher.final('utf8');

        const plainAAD = bufferAAD.toString('utf8')

        return [decrypted,plainAAD];
    }
};