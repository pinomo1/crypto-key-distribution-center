import { CryptoFunction } from "./crypto_function";

export class MiniRSA extends CryptoFunction<[number, number, number]> {
    private isPrime(n: number): boolean {
        if (n <= 1) return false;
        if (n <= 3) return true;
        if (n % 2 == 0 || n % 3 == 0) return false;
        let i = 5;
        while (i * i <= n) {
            if (n % i == 0 || n % (i + 2) == 0) return false;
            i += 6;
        }
        return true;
    }

    private isRelativePrime(a: number, b: number): boolean {
        let temp: number;
        let x = a;
        let y = b;
        while (y != 0) {
            temp = x;
            x = y;
            y = temp % y;
        }
        return x == 1;
    }

    generateKey(): [number, number, number] {
        let isSuccess: boolean;
        let e = 0;
        let d = 0;
        let n = 0;
        do {
            try {
                isSuccess = true;
                let p: number;
                let q: number;
                do {
                    p = Math.floor(Math.random() * 90) + 10;
                    q = Math.floor(Math.random() * 90) + 10;
                } while (!this.isPrime(p) || !this.isPrime(q) || q === p);
                n = p * q;

                const phi = (p - 1) * (q - 1);

                do {
                    e = Math.floor(Math.random() * (phi - 2)) + 2;
                } while (!this.isRelativePrime(e, phi));

                d = Array.from({length: phi}, (_, i) => i + 2).reverse().find(it => (it * e) % phi === 1 && it !== e) || 0;
            }
            catch (ex) {
                isSuccess = false;
            }
        } while (!isSuccess);

        this.loadKey([e, d, n]);

        return [e, d, n];
    }

    isValidForKey(potentialKey: [number, number, number]): boolean {
        return potentialKey[0] !== 0 && potentialKey[2] !== 0;
    }

    crypt(str: string, isEncrypt: boolean): string {
        const ed = isEncrypt ? this.key[0] : this.key[1];
        if (ed === 0){
            throw new Error("Private Key Not Set");
        }
        const n = this.key[2];
        let cipherText = "";
        for (let i = 0; i < str.length; i++) {
            const ch = str[i];
            const temp = ch.charCodeAt(0);
            let k = 1;
            for (let j = 0; j < ed; j++) {
                k *= temp;
                k %= n;
            }
            cipherText += String.fromCharCode(k);
        }
        return cipherText;
    }
}