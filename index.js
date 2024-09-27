function hmacSha1(key, message) {
    const blockSize = 64;
    let keyBytes = stringToBytes(key);

    if (keyBytes.length > blockSize) {
        keyBytes = sha1(keyBytes);
    }

    if (keyBytes.length < blockSize) {
        keyBytes = keyBytes.concat(new Array(blockSize - keyBytes.length).fill(0));
    }

    const oKeyPad = keyBytes.map(byte => byte ^ 0x5c);
    const iKeyPad = keyBytes.map(byte => byte ^ 0x36);

    const innerHash = sha1(iKeyPad.concat(stringToBytes(message)));
    return sha1(oKeyPad.concat(innerHash));
}

function sha1(bytes) {
    function rotate_left(n, s) {
        return (n << s) | (n >>> (32 - s));
    }

    function lsb_hex(val) {
        let str = '';
        for (let i = 0; i <= 6; i += 2) {
            let vh = (val >>> (i * 4 + 4)) & 0x0f;
            let vl = (val >>> (i * 4)) & 0x0f;
            str += vh.toString(16) + vl.toString(16);
        }
        return str;
    }

    function utf8_encode(string) {
        string = string.replace(/\r\n/g, '\n');
        let utftext = '';

        for (let n = 0; n < string.length; n++) {
            let c = string.charCodeAt(n);

            if (c < 128) {
                utftext += String.fromCharCode(c);
            } else if (c > 127 && c < 2048) {
                utftext += String.fromCharCode((c >> 6) | 192);
                utftext += String.fromCharCode((c & 63) | 128);
            } else {
                utftext += String.fromCharCode((c >> 12) | 224);
                utftext += String.fromCharCode(((c >> 6) & 63) | 128);
                utftext += String.fromCharCode((c & 63) | 128);
            }
        }

        return utftext;
    }

    let blockstart;
    let i, j;
    let W = new Array(80);
    let H0 = 0x67452301;
    let H1 = 0xEFCDAB89;
    let H2 = 0x98BADCFE;
    let H3 = 0x10325476;
    let H4 = 0xC3D2E1F0;

    // Ensure that the input `bytes` is converted properly to a string for encoding
    const msg = utf8_encode(String.fromCharCode.apply(null, bytes));
    let msg_len = msg.length;

    let word_array = [];
    for (i = 0; i < msg_len - 3; i += 4) {
        j = (msg.charCodeAt(i) << 24) |
            (msg.charCodeAt(i + 1) << 16) |
            (msg.charCodeAt(i + 2) << 8) |
            msg.charCodeAt(i + 3);
        word_array.push(j);
    }

    switch (msg_len % 4) {
        case 0:
            i = 0x080000000;
            break;
        case 1:
            i = (msg.charCodeAt(msg_len - 1) << 24) | 0x0800000;
            break;
        case 2:
            i = (msg.charCodeAt(msg_len - 2) << 24) | (msg.charCodeAt(msg_len - 1) << 16) | 0x08000;
            break;
        case 3:
            i = (msg.charCodeAt(msg_len - 3) << 24) | (msg.charCodeAt(msg_len - 2) << 16) | (msg.charCodeAt(msg_len - 1) << 8) | 0x80;
            break;
    }

    word_array.push(i);

    while ((word_array.length % 16) != 14) {
        word_array.push(0);
    }

    word_array.push(msg_len >>> 29);
    word_array.push((msg_len << 3) & 0x0ffffffff);

    for (blockstart = 0; blockstart < word_array.length; blockstart += 16) {
        for (i = 0; i < 16; i++) {
            W[i] = word_array[blockstart + i];
        }
        for (i = 16; i <= 79; i++) {
            W[i] = rotate_left(W[i - 3] ^ W[i - 8] ^ W[i - 14] ^ W[i - 16], 1);
        }

        let A = H0;
        let B = H1;
        let C = H2;
        let D = H3;
        let E = H4;

        for (i = 0; i <= 19; i++) {
            let temp = (rotate_left(A, 5) + ((B & C) | (~B & D)) + E + W[i] + 0x5A827999) & 0x0ffffffff;
            E = D;
            D = C;
            C = rotate_left(B, 30);
            B = A;
            A = temp;
        }

        for (i = 20; i <= 39; i++) {
            let temp = (rotate_left(A, 5) + (B ^ C ^ D) + E + W[i] + 0x6ED9EBA1) & 0x0ffffffff;
            E = D;
            D = C;
            C = rotate_left(B, 30);
            B = A;
            A = temp;
        }

        for (i = 40; i <= 59; i++) {
            let temp = (rotate_left(A, 5) + ((B & C) | (B & D) | (C & D)) + E + W[i] + 0x8F1BBCDC) & 0x0ffffffff;
            E = D;
            D = C;
            C = rotate_left(B, 30);
            B = A;
            A = temp;
        }

        for (i = 60; i <= 79; i++) {
            let temp = (rotate_left(A, 5) + (B ^ C ^ D) + E + W[i] + 0xCA62C1D6) & 0x0ffffffff;
            E = D;
            D = C;
            C = rotate_left(B, 30);
            B = A;
            A = temp;
        }

        H0 = (H0 + A) & 0x0ffffffff;
        H1 = (H1 + B) & 0x0ffffffff;
        H2 = (H2 + C) & 0x0ffffffff;
        H3 = (H3 + D) & 0x0ffffffff;
        H4 = (H4 + E) & 0x0ffffffff;
    }

    let hash = [
        (H0 >> 24) & 0xff, (H0 >> 16) & 0xff, (H0 >> 8) & 0xff, H0 & 0xff,
        (H1 >> 24) & 0xff, (H1 >> 16) & 0xff, (H1 >> 8) & 0xff, H1 & 0xff,
        (H2 >> 24) & 0xff, (H2 >> 16) & 0xff, (H2 >> 8) & 0xff, H2 & 0xff,
        (H3 >> 24) & 0xff, (H3 >> 16) & 0xff, (H3 >> 8) & 0xff, H3 & 0xff,
        (H4 >> 24) & 0xff, (H4 >> 16) & 0xff, (H4 >> 8) & 0xff, H4 & 0xff
    ];

    return hash;  // 返回字节数组
}



function stringToBytes(str) {
    return Array.from(str).map(char => char.charCodeAt(0));
}

function bytesToHex(bytes) {
    if (!Array.isArray(bytes)) {
        throw new TypeError('Expected an array of bytes');
    }

    return bytes.map(byte => {
        let hex = byte.toString(16);
        return hex.length === 1 ? '0' + hex : hex;
    }).join('');
}


function urlEncode(input) {
    return encodeURIComponent(input);
}
