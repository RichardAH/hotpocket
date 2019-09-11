const fs = require('fs')
const ws_api = require('ws');
const sodium = require('libsodium-wrappers')
const crypto = require('crypto')
const readline = require('readline')
const pipe = require('posix-pipe-fork-exec')

// sodium has a trigger when it's ready, we will wait and execute from there
sodium.ready.then(main).catch((e)=>{console.log(e)})


function main() {

    var keys = sodium.crypto_sign_keypair()
    

    // check for client keys
    if (!fs.existsSync('.hp_client_keys')) {
        keys.privateKey = sodium.to_hex(keys.privateKey)
        keys.publicKey = sodium.to_hex(keys.publicKey)
        fs.writeFileSync('.hp_client_keys', JSON.stringify(keys))
    } else {
        keys = JSON.parse(fs.readFileSync('.hp_client_keys'))
        keys.privateKey = Uint8Array.from(Buffer.from(keys.privateKey, 'hex'))
        keys.publicKey = Uint8Array.from(Buffer.from(keys.publicKey, 'hex'))
    }


    var server = 'ws://localhost:8080'

    if (process.argv.length == 3) server = 'ws://localhost:' + process.argv[2]

    if (process.argv.length == 4) server = 'ws://' + process.argv[2] + ':' + process.argv[3]

    var ws = new ws_api( server )

    /* anatomy of a public challenge
       {
       hotpocket: 0.1,
       type: 'public_challenge',
       challenge: '265aefae7beb0e4000fc871db797f70f'
       }
     */


    // if the console ctrl + c's us we should close ws gracefully
    process.once('SIGINT', function (code) {
    console.log('SIGINT received...');
        ws.close()  
    });

    ws.on('message', (m) => {
        console.log("-----raw message-----")
        console.log(m)
        console.log("---------------------")
        
        try {
            m = JSON.parse(m)
        } catch (e) {
            return
        }

        if (m.type != 'public_challenge') return

        console.log("received challenge message")
        console.log(m)

        var response = {
            sig: sodium.to_hex(
                 sodium.crypto_sign_detached(
                 m.challenge, keys.privateKey)),
            pubkey: sodium.to_hex(keys.publicKey),
            timestamp: Math.floor(Date.now()/1000),
            challenge: m.challenge,
            type: 'helo'
        }

        console.log('our public key is: ' + sodium.to_hex(keys.publicKey))
        // start listening for stdin
        const rl = readline.createInterface({
            input: process.stdin,
            output: process.stdout
        });

        ws.send(JSON.stringify(response))

        var input_pump = () => { 
            rl.question('', (answer) => {
                ws.send(answer + "\n")
                input_pump()
            })
        }
        input_pump()

    })
}


