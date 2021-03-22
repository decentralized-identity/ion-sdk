/**
 * @waiting/base64
 * Base64 encoding/decoding in pure JS on both modern Browsers and Node.js. Also supports URL-safe base64
 *
 * @version 4.2.9
 * @author waiting
 * @license MIT
 * @link https://github.com/waitingsong/base64#readme
 */

const baseChars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
const lookup = [];
const revLookup = [];
for (let i = 0, len = baseChars.length; i < len; ++i) {
    lookup[i] = baseChars[i];
    revLookup[baseChars.charCodeAt(i)] = i;
}
// Support decoding URL-safe base64 strings, as Node.js does.
// See: https://en.wikipedia.org/wiki/Base64#URL_applications
revLookup['-'.charCodeAt(0)] = 62;
revLookup['_'.charCodeAt(0)] = 63;
const ErrMsg = {
    base64Invalidlength: 'Invalid string. Length must be a multiple of 4 and positive',
    base64InvalidEqualPosition: 'Invalid base64 string, char "=" should not exists or at posiont >= 2',
    encodeInvalidParam: 'Invalid value of parameter of encode(), should be string|number|bigint',
    fromArrayBufferInvalidParam: 'Invalid input, should be ArrayBuffer or Uint8Array',
    notString: 'Invalid value of parameter, should be string',
    notValidB64String: 'Valid base64 string only matches /^[a-zA-Z0-9+/_-]+={0,2}$/',
    notValidB64URLString: 'Valid URL-safe base64 string only matchs /^[a-zA-Z0-9_-]+$/',
    notValidB64Length: 'Valid base64 string contains as least 4 chars',
    notValidB64URLLength: 'Valid URL-safe base64 string contains as least 2 chars',
    startMustGrossOrEqualToEnd: 'Parameters of start should less then or equal to end',
    startMustGrossToEnd: 'Parameters of start should less then end',
    textEncoderUndefined: 'TextEncoder undefined!',
    textDecoderUndefined: 'TextDecoder undefined!',
};
const defaultConfig = {
    forceBrowser: false,
};

// rewrite from https://github.com/beatgammit/base64-js
function fromUint8Array(input) {
    /* tslint:disable: no-bitwise */
    const len = input.length;
    const extraBytes = len % 3; // if we have 1 byte left, pad 2 bytes
    const len2 = len - extraBytes;
    const maxChunkLength = 12000; // must be multiple of 3
    const parts = new Array(Math.ceil(len2 / maxChunkLength) + (extraBytes ? 1 : 0));
    let curChunk = 0;

    // go through the array every three bytes, we'll deal with trailing stuff later
    for (let i = 0, nextI = 0; i < len2; i = nextI) {
        nextI = i + maxChunkLength;
        parts[curChunk] = encodeChunk(input, i, Math.min(nextI, len2));
        curChunk += 1;
    }
    // pad the end with zeros, but make sure to not forget the extra bytes
    if (extraBytes === 1) {
        const tmp = input[len2] & 0xFF;

        parts[curChunk] = lookup[tmp >> 2] + lookup[tmp << 4 & 0x3F] + '==';
    }
    else if (extraBytes === 2) {
        const tmp = (input[len2] & 0xFF) << 8 | (input[len2 + 1] & 0xFF);

        parts[curChunk] = lookup[tmp >> 10] +
            lookup[tmp >> 4 & 0x3F] +
            lookup[tmp << 2 & 0x3F] +
            '=';
    }
    /* tslint:enable: no-bitwise */
    return parts.join('')
}
function encodeChunk(input, start, end) {
    if (start >= end) {
        throw new Error(ErrMsg.startMustGrossToEnd)
    }
    const arrLen = Math.ceil((end - start) / 3);
    const ret = new Array(arrLen);

    /* tslint:disable: no-bitwise */
    for (let i = start, curTriplet = 0; i < end; i += 3, curTriplet += 1) {
        ret[curTriplet] = tripletToBase64((input[i] & 0xFF) << 16 |
            (input[i + 1] & 0xFF) << 8 |
            (input[i + 2] & 0xFF));
    }
    /* tslint:enable: no-bitwise */
    return ret.join('')
}
function tripletToBase64(pos) {
    /* tslint:disable: no-bitwise */
    return lookup[pos >> 18 & 0x3F] +
        lookup[pos >> 12 & 0x3F] +
        lookup[pos >> 6 & 0x3F] +
        lookup[pos & 0x3F]
    /* tslint:enable: no-bitwise */
}

function parseEncodeInputString(input) {
    const ret = typeof input === 'string'
        ? input
        // tslint:disable-next-line: valid-typeof
        : (typeof input === 'number' || typeof input === 'bigint' ? input.toString() : null);

    if (ret === null) {
        throw new TypeError(ErrMsg.encodeInvalidParam)
    }
    return ret
}
function parseDecodeInputBase64(base64) {
    if (typeof base64 !== 'string') {
        throw new TypeError(ErrMsg.notString)
    }
    else if (!validB64Chars(base64)) {
        throw new TypeError(ErrMsg.notValidB64String)
    }
    return base64
}
function parseTextEncoder(textEncoder) {
    if (typeof textEncoder === 'function') {
        return textEncoder
    }
    else if (typeof TextEncoder === 'function') {
        return TextEncoder
    }
    else {
        throw new TypeError(ErrMsg.textEncoderUndefined)
    }
}
function parseTextDecoder(textDecoder) {
    if (typeof textDecoder === 'function') {
        return textDecoder
    }
    else if (typeof TextDecoder === 'function') {
        return TextDecoder
    }
    else {
        throw new TypeError(ErrMsg.textDecoderUndefined)
    }
}
/** Whether string contains valid base64 characters */
function validB64Chars(input) {
    return /^[a-zA-Z0-9+/_-]+={0,2}$/.test(input)
}
/** Whether string contains valid URL-safe base64 characters */
function validB64URLChars(input) {
    return /^[a-zA-Z0-9_-]+$/.test(input)
}
/** Validate input is valid base64 string or throw error */
function validateB64(input) {
    const status = testB64(input);

    if (status !== true) {
        throw new Error(status)
    }
}
/** Validate input is valid URL-safe base64 string or throw error */
function validateB64URL(input) {
    const status = testB64URL(input);

    if (status !== true) {
        throw new Error(status)
    }
}
/** Return true for valid base64 input, error message for invalid */
function testB64(input) {
    if (typeof input !== 'string') {
        return ErrMsg.notString
    }
    else if (!validB64Chars(input)) {
        return ErrMsg.notValidB64String
    }
    else if (input.length < 4) {
        return ErrMsg.notValidB64Length
    }
    else if (input.length % 4 !== 0) {
        return ErrMsg.base64Invalidlength
    }
    return true
}
/** Return true for valid URL-safe base64 input,  error message for invalid */
function testB64URL(input) {
    if (typeof input !== 'string') {
        return ErrMsg.notString
    }
    else if (!validB64URLChars(input)) {
        return ErrMsg.notValidB64URLString
    }
    else if (input.length < 2) { // URL-safe at least 2
        return ErrMsg.notValidB64URLLength
    }
    return true
}
/** Whether running in Node.js */
function isRunningInNodejs() {
    // Buffer exists under karma testing
    /* istanbul ignore next */
    return typeof process === 'object' && typeof Buffer === 'function' && typeof window === 'undefined'
        ? true
        : false
}
/** Whether input is instance of ArrayBuffer */
function isArrayBuffer(buffer) {
    return buffer && buffer instanceof ArrayBuffer ? true : false
}
/** Whether input is instance of Uint8Array */
function isUint8Array(buffer) {
    return ArrayBuffer.isView(buffer) && (buffer instanceof Uint8Array)
        ? true
        : false
}
/**
 * Convert base64 string to URL-safe base64 string.
 * Replace "+" to "-" and "/" to "_", and Remove "="
 *
 * @see https://en.wikipedia.org/wiki/Base64#URL_applications
 */
function b64toURLSafe(base64) {
    validateB64(base64);
    const pos = base64.indexOf('=');

    return pos > 0
        ? base64.slice(0, pos).replace(/\+/g, '-').replace(/\//g, '_')
        : base64.replace(/\+/g, '-').replace(/\//g, '_')
}
/**
 * Convert URL-safe base64 string to base64 string.
 * Replace "-" to "+" and "_" to "/", and pad with "="
 *
 * @see https://en.wikipedia.org/wiki/Base64#URL_applications
 */
function b64fromURLSafe(base64) {
    validateB64URL(base64);
    const str = base64.replace(/-/g, '+').replace(/_/g, '/');

    return b64PadSuffix(str)
}
function b64PadSuffix(input) {
    let num = 0;
    const mo = input.length % 4;

    switch (mo) {
        case 3:
            num = 1;
            break
        case 2:
            num = 2;
            break
        case 0:
            num = 0;
            break
        default:
            throw new Error(ErrMsg.notValidB64URLLength)
    }
    return input + '='.repeat(num)
}

// rewrite from https://github.com/beatgammit/base64-js
function toUint8Array(b64) {
    /* tslint:disable: no-bitwise */
    const lens = getLens(b64);
    const validLen = lens[0];
    const placeHoldersLen = lens[1];
    const arr = new Uint8Array(_byteLength(validLen, placeHoldersLen));
    let curByte = 0;
    // if there are placeholders, only get up to the last complete 4 chars
    const len = placeHoldersLen
        ? validLen - 4
        : validLen;
    let i = 0;

    for (; i < len; i += 4) {
        const tmp = revLookup[b64.charCodeAt(i)] << 18 |
            revLookup[b64.charCodeAt(i + 1)] << 12 |
            revLookup[b64.charCodeAt(i + 2)] << 6 |
            revLookup[b64.charCodeAt(i + 3)];

        arr[curByte++] = tmp >> 16 & 0xFF;
        arr[curByte++] = tmp >> 8 & 0xFF;
        arr[curByte++] = tmp & 0xFF;
    }
    if (placeHoldersLen === 2) {
        arr[curByte] = revLookup[b64.charCodeAt(i)] << 2 |
            revLookup[b64.charCodeAt(i + 1)] >> 4;
    }
    else if (placeHoldersLen === 1) {
        const tmp = revLookup[b64.charCodeAt(i)] << 10 |
            revLookup[b64.charCodeAt(i + 1)] << 4 |
            revLookup[b64.charCodeAt(i + 2)] >> 2;

        arr[curByte++] = tmp >> 8 & 0xFF;
        arr[curByte] = tmp & 0xFF;
    }
    /* tslint:enable: no-bitwise */
    return arr
}
function getLens(input) {
    /* tslint:disable: no-bitwise */
    const len = input.length;

    if (len & 3 || len <= 0) {
        throw new Error(ErrMsg.base64Invalidlength)
    }
    // Trim off extra bytes after placeholder bytes are found
    // See: https://github.com/beatgammit/base64-js/issues/42
    let validLen = input.indexOf('=');

    if (validLen === -1) {
        validLen = len;
    }
    // 0 to 3 characters of padding so total length is a multiple of 4
    const placeHoldersLen = 3 - ((validLen + 3) & 3);

    /* tslint:enable: no-bitwise */
    return [validLen, placeHoldersLen]
}
function _byteLength(validLen, placeHoldersLen) {
    // tslint:disable-next-line: no-bitwise
    return (((validLen + placeHoldersLen) * 3) >> 2) - placeHoldersLen
}

function browserEncode(input, textEncoder) {
    const str = parseEncodeInputString(input);
    const Encoder = parseTextEncoder(textEncoder);
    const u8arr = new Encoder().encode(str);
    const ret = fromBuffer(u8arr);

    return ret
}
/** Encode to base64, source from ArrayBuffer or Uint8Array */
function fromBuffer(buf) {
    let input;

    if (!buf) {
        throw new TypeError(ErrMsg.fromArrayBufferInvalidParam)
    }
    else if (isUint8Array(buf)) {
        input = buf;
    }
    else if (isArrayBuffer(buf)) {
        input = new Uint8Array(buf);
    }
    else {
        throw new TypeError(ErrMsg.fromArrayBufferInvalidParam)
    }
    return fromUint8Array(input)
}
function browserDecode(base64, outputEncoding, textDecoder) {
    const Decoder = parseTextDecoder(textDecoder);
    const u8arr = toBuffer(base64);
    const ret = new Decoder(outputEncoding).decode(u8arr);

    return ret
}
function toBuffer(base64) {
    const str = parseDecodeInputBase64(base64);
    const u8arr = toUint8Array(str);

    return u8arr
}

function nodeEncode(input) {
    const str = parseEncodeInputString(input);
    const ret = Buffer.from(str).toString('base64');

    return ret
}
function nodeDecode(base64, outputEncoding) {
    const str = parseDecodeInputBase64(base64);
    const ret = Buffer.from(str, 'base64').toString(outputEncoding);

    return ret
}
/** Encode to base64, source from ArrayBuffer or Uint8Array */
function fromBuffer$1(buf) {
    let inst;

    if (!buf) {
        throw new TypeError(ErrMsg.fromArrayBufferInvalidParam)
    }
    else if (isUint8Array(buf)) {
        inst = Buffer.from(buf);
    }
    else if (isArrayBuffer(buf)) {
        inst = Buffer.from(buf);
    }
    else {
        throw new TypeError(ErrMsg.fromArrayBufferInvalidParam)
    }
    const ret = inst.toString('base64');

    return ret
}

/** Encode to base64, source from string | number | bigint */
function b64encode(input, textEncoder) {
    const ret = isRunningInNodejs() && !defaultConfig.forceBrowser
        ? nodeEncode(input)
        : browserEncode(input, textEncoder);

    return ret
}
/** Decode base64 to string */
function b64decode(base64, outputEncoding = 'utf-8', textDecoder) {
    const ret = isRunningInNodejs() && !defaultConfig.forceBrowser
        ? nodeDecode(base64, outputEncoding)
        : browserDecode(base64, outputEncoding, textDecoder);

    return ret
}
/** Encode to base64, source from ArrayBuffer or Uint8Array */
function b64fromBuffer(buffer) {
    const ret = isRunningInNodejs() && !defaultConfig.forceBrowser
        ? fromBuffer$1(buffer)
        : fromBuffer(buffer);

    return ret
}
/**
 * Calculate buffer.byteLength from base64
 *
 * base64 is 4/3 + up to two characters of the original data
 */
function b64byteLength(base64) {
    const lens = getLens(base64);
    const validLen = lens[0];
    const placeHoldersLen = lens[1];

    return _byteLength(validLen, placeHoldersLen)
}
/**
 * Encode to URL-safe base64, source from string | number | bigint.
 * Replace "+" to "-" and "/" to "_", and Remove "=".
 *
 * Note: using b64toURLSafe() for converting base64 string to URL-safe base64 string
 *
 * @see https://en.wikipedia.org/wiki/Base64#URL_applications
 */
function b64urlEncode(input, textEncoder) {
    const b64 = b64encode(input, textEncoder);

    return b64toURLSafe(b64)
}
/**
 * Encode to URL-safe base64, source from ArrayBuffer or Uint8Array
 *
 * @see https://en.wikipedia.org/wiki/Base64#URL_applications
 */
function b64urlFromBuffer(buffer) {
    const b64 = b64fromBuffer(buffer);

    return b64toURLSafe(b64)
}
/**
 * Decode URL-safe base64 to original string.
 *
 * Note: using b64fromURLSafe() for converting URL-safe base64 string to base64 string
 *
 * @see https://en.wikipedia.org/wiki/Base64#URL_applications
 */
function b64urlDecode(input, outputEncoding = 'utf-8', textDecoder) {
    const str = b64PadSuffix(input); // for URL-safe

    return b64decode(str, outputEncoding, textDecoder)
}

export { ErrMsg, b64byteLength, b64decode, b64encode, b64fromBuffer, b64fromURLSafe, b64toURLSafe, b64urlDecode, b64urlEncode, b64urlFromBuffer, isArrayBuffer, isUint8Array, testB64, testB64URL, validB64Chars, validB64URLChars };
