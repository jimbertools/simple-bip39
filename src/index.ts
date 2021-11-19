import {
    getRandomBytes,
    deriveChecksumBits,
    bytesToHex,
    hexToBytes,
    binaryToByte,
    normalize,
    bytesToBinary,
    lpad,
} from './utils/utils';
import defaultWordList from './languages/english';

export const generateMnemonic = (strength: number = 128): string => {
    const bytes = getRandomBytes(strength / 8);
    return entropyToMnemonic(bytes);
};

export function mnemonicToEntropy(mnemonic: string): string {
    const wordList = defaultWordList;

    if (!wordList) {
        throw new Error('WORDLIST_REQUIRED');
    }

    var words = normalize(mnemonic).split(' ');

    if (words.length % 3 !== 0) {
        throw new Error('INVALID_MNEMONIC');
    }

    var bits = words
        .map(function (word) {
            var index = wordList.indexOf(word);
            if (index === -1) {
                throw new Error('INVALID_MNEMONIC');
            }
            return lpad(index.toString(2), '0', 11);
        })
        .join('');

    var dividerIndex = Math.floor(bits.length / 33) * 32;
    var entropyBits = bits.slice(0, dividerIndex);
    var checksumBits = bits.slice(dividerIndex);
    var entropyBytes = entropyBits.match(/(.{1,8})/g).map(binaryToByte);

    if (entropyBytes.length < 16) {
        throw new Error('INVALID_ENTROPY');
    }
    if (entropyBytes.length > 32) {
        throw new Error('INVALID_ENTROPY');
    }
    if (entropyBytes.length % 4 !== 0) {
        throw new Error('INVALID_ENTROPY');
    }

    var entropy = entropyBytes;
    var newChecksum = deriveChecksumBits(Uint8Array.from(entropy));

    if (newChecksum !== checksumBits) {
        throw new Error('INVALID_CHECKSUM');
    }

    return bytesToHex(Uint8Array.from(entropy));
}

export const entropyToMnemonic = (entropyInput: string | Uint8Array): string => {
    const entropy = typeof entropyInput === 'string' ? hexToBytes(entropyInput) : entropyInput;

    if (entropy.length < 16) {
        throw new Error('INVALID_ENTROPY');
    }
    if (entropy.length > 32) {
        throw new Error('INVALID_ENTROPY');
    }
    if (entropy.length % 4 !== 0) {
        throw new Error('INVALID_ENTROPY');
    }

    const entropyBits = bytesToBinary(Array.from(entropy));
    const checksumBits = deriveChecksumBits(entropy);

    const bits = entropyBits + checksumBits;
    const chunks = bits.match(/(.{1,11})/g);
    const words = chunks.map(binary => {
        const index = binaryToByte(binary);
        return defaultWordList[index];
    });

    return words.join(' ');
};
