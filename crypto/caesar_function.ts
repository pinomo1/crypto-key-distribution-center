import { CryptoFunction } from "./crypto_function";

export class CaesarFunction extends CryptoFunction<number> {
    crypt(str: string, isEncrypt: boolean): string {
        let copyStr = str;
        if (isEncrypt) {
            copyStr = copyStr.toLowerCase();
        }
        let result = "";
        for (let i = 0; i < copyStr.length; i++) {
            const c = copyStr.charCodeAt(i);
            const newChar = String.fromCharCode(c + (isEncrypt ? 1 : -1) * this.key);
            result += newChar;
        }
        return result;
    }

    generateKey(): number {
        const rand = Math.floor(Math.random() * 1024) + 1;
        this.loadKey(rand);
        return this.key;
    }

    isValidForKey(potentialKey: number): boolean {
        return potentialKey > 0 && potentialKey < 1024;
    }
}