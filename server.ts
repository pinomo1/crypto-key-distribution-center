import { createServer } from "http";
import { networkInterfaces } from "node:os";
import dgram from "node:dgram";
import { CaesarFunction } from "./crypto/caesar_function";
import { MiniRSA } from "./crypto/miniRSA";

const multicastAddress = "224.0.2.63";
const multicastSocket: dgram.Socket = dgram.createSocket({type: "udp4", reuseAddr: true});
const localAddresses: string[] = [];

const nets = networkInterfaces();

const tokenKeys = new Map<number, [number, number]>();

for (const name of Object.keys(nets)) {
    for (const net of nets[name]!) {
        if (net.family === 'IPv4') {
            localAddresses.push(name + " - " + net.address);
        }
    }
}

multicastSocket.on('message', (msg, rinfo) => {
    let message = msg.toString();
    let address = rinfo.address;
    let port = rinfo.port;
    console.log(`Received ${message} from ${address}:${port}`);
    if (message == "DISCOVER"){
        let reply = Buffer.from("OFFER");
        multicastSocket.send(reply, port, address);
    }
});

const httpServer = createServer(function(req,res){
    let headers = {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'POST',
        'Access-Control-Allow-Headers': 'Origin, X-Requested-With, Content-Type, Accept',
        'Content-Type': 'application/json'
    };
    
    if (req.method == "OPTIONS"){
        res.writeHead(200, headers);
        res.end(JSON.stringify({}));
    }

    else if (req.method == "POST"){
        let body = "";

        req.on('data', (chunk) => {
            body += chunk.toString();
        });

        req.on('end', () => {
            let json : any;
            try{
                json = JSON.parse(body);
            }
            catch(e){
                res.writeHead(400, headers);
                res.end(JSON.stringify({error: "Invalid JSON"}));
                return;
            }
            if (req.url == "/api/canaccess"){
                res.writeHead(200, headers);
                res.end();
            }

            else if (req.url == "/api/new"){
                let publicKey : [number, number];
                let token : number;
                if (json.publicKey == undefined || json.token == undefined){
                    res.writeHead(400, headers);
                    res.end(JSON.stringify({error: "Invalid request"}));
                    return;
                }
                publicKey = json.publicKey;
                token = json.token;
                tokenKeys.set(token, publicKey);
                console.log("New token: " + token + " with public key: " + publicKey);
                res.writeHead(200, headers);
                res.end(JSON.stringify({}));
            }

            else if (req.url == "/api/verify"){
                let token : number;
                let nonce : number;
                let publicKeyA : [number, number];
                if (json.token == undefined || json.nonce == undefined || json.publicKey == undefined){
                    res.writeHead(400, headers);
                    res.end(JSON.stringify({error: "Invalid request"}));
                    return;
                }
                token = json.token;
                nonce = json.nonce;
                publicKeyA = json.publicKey;
                let publicKeyB = tokenKeys.get(token);
                if (publicKeyB == undefined){
                    res.writeHead(404, headers);
                    res.end(JSON.stringify({error: "Not found"}));
                    return;
                }

                let caesar : CaesarFunction = new CaesarFunction();
                let rsa : MiniRSA = new MiniRSA();
                rsa.loadKey([publicKeyA[0], 0, publicKeyA[1]]);

                let objA = {
                    sessionKey: caesar.key,
                    token: token,
                    timestamp: Date.now(),
                    nonce: nonce
                }

                let encryptedA = rsa.encrypt(JSON.stringify(objA));

                let objB = {
                    sessionKey: caesar.key,
                    token: token,
                    timestamp: Date.now(),
                }

                rsa.loadKey([publicKeyB[0], 0, publicKeyB[1]]);

                let encryptedB = rsa.encrypt(JSON.stringify(objB));

                let response = {
                    encryptedA: encryptedA,
                    encryptedB: encryptedB
                }

                console.log("Session key: " + caesar.key + " for token: " + token);

                res.writeHead(200, headers);
                res.end(JSON.stringify(response));
            }

            else{
                res.writeHead(404, headers);
                res.end(JSON.stringify({error: "Not found"}));
            }
        });
    }
    else{
        res.writeHead(404, headers);
        res.end(JSON.stringify({error: "Not found"}));
    }
});

const port = 8003;

function logInterface(){
    console.log("Available interfaces:");
    for (let i = 0; i < localAddresses.length; i++){
        console.log(localAddresses[i] + ":" + port);
    }
    console.log("Multicast address: " + multicastAddress);
}

logInterface();

httpServer.listen(port, () => {
    console.log(`listening on *:${port}`);
});

multicastSocket.addMembership(multicastAddress);
