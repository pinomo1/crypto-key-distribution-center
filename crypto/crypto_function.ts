
export abstract class CryptoFunction<T> {
    public key: T;

    constructor() {
        this.key = this.generateKey();
    }

    crypt(str: string, isEncrypt: boolean): string {
        return isEncrypt ? this.encrypt(str) : this.decrypt(str);
    }

    decrypt(str: string): string {
        return this.crypt(str, false);
    }

    encrypt(str: string): string {
        return this.crypt(str, true);
    }

    abstract generateKey(): T;

    abstract isValidForKey(potentialKey: T): boolean;

    loadKey(key: T) {
        if (!this.isValidForKey(key)) {
            throw new Error("Invalid Key Exception");
        }
        this.key = key;
    }
}