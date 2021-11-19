import { createHash } from 'sha256-uint8array';

export const getRandomBytes = (length: number): Uint8Array => {
    var randomBytesArray = new Uint8Array(length);

    for (var i = 0; i < length; i += 65536) {
        globalThis.crypto.getRandomValues(randomBytesArray.subarray(i, i + Math.min(length - i, 65536)));
    }

    return randomBytesArray;
};

export const normalize = (str: string): string => {
    return (str || '').normalize('NFKD');
};

export const lpad = (str: string, padString: string, length: number): string => {
    while (str.length < length) {
        str = padString + str;
    }

    return str;
};

export const binaryToByte = (bin: string): number => {
    return parseInt(bin, 2);
};

export const bytesToBinary = (bytes: number[]): string => {
    return bytes.map(x => lpad(x.toString(2), '0', 8)).join('');
};

export const hexToBytes = (hexString: string): Uint8Array => {
    return new Uint8Array(hexString.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));
};

export const bytesToHex = (bytes: Uint8Array): string => {
    return bytes.reduce((str, byte) => str + byte.toString(16).padStart(2, '0'), '');
};

export const deriveChecksumBits = (entropy: Uint8Array): string => {
    var ENT = entropy.length * 8;
    var CS = ENT / 32;

    var hash = createHash().update(entropy).digest();

    return bytesToBinary(Array.from(hash)).slice(0, CS);
};
