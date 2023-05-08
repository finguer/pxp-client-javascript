/**
 * Pxp Rest client v2 para usar en javascript puro o jquery
 * Connect with pxp framework php 7 version
 * @author : Favio Figueroa
 * */
const _encryptMethodLength = () => {
    const encryptMethod = 'AES-256-CBC';
    // get only number from string.
    // @link https://stackoverflow.com/a/10003709/128761 Reference.
    const aesNumber = encryptMethod.match(/\d+/)[0];
    return parseInt(aesNumber);
};// encryptMethodLength

const encrypt = (string, key) => {
    const iv = CryptoJS.lib.WordArray.random(16);// the reason to be 16, please read on `encryptMethod` property.

    const salt = CryptoJS.lib.WordArray.random(256);
    const iterations = 999;
    const encryptMethodLength = (_encryptMethodLength() / 4);// example: AES number is 256 / 4 = 64
    const hashKey = CryptoJS.PBKDF2(key, salt, {
        'hasher': CryptoJS.algo.SHA512,
        'keySize': (encryptMethodLength / 8),
        'iterations': iterations
    });

    const encrypted = CryptoJS.AES.encrypt(string, hashKey, {'mode': CryptoJS.mode.CBC, 'iv': iv});
    const encryptedString = CryptoJS.enc.Base64.stringify(encrypted.ciphertext);

    const output = {
        'ciphertext': encryptedString,
        'iv': CryptoJS.enc.Hex.stringify(iv),
        'salt': CryptoJS.enc.Hex.stringify(salt),
        'iterations': iterations
    };

    return CryptoJS.enc.Base64.stringify(CryptoJS.enc.Utf8.parse(JSON.stringify(output)));
}// encrypt

const doEncrypt = ({username, password}) => {
    const prefix = uuidv4();
    const md5Pass = CryptoJS.MD5(password).toString();
    const encrypted = encrypt(prefix + '$$' + username, md5Pass);
    return encrypted;


}