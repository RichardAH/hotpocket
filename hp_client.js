const fs = require('fs')
const ws_api = require('ws');
const sodium = require('libsodium-wrappers')
const crypto = require('crypto')
const readline = require('readline')


// sodium has a trigger when it's ready, we will wait and execute from there
sodium.ready.then(main).catch((e)=>{console.log(e)})


function main() {

    var keys = sodium.crypto_sign_keypair()
    var ws = new ws_api('ws://localhost:8080')

/*
{
  hotpocket: 0.1,
  type: 'public_challenge',
  challenge: '265aefae7beb0e4000fc871db797f70f'
}
*/

    ws.on('message', (m)=>{
        m = JSON.parse(m)
        if (m.type == 'public_challenge') {

            console.log("received challenge message")
            console.log(m)

            var response = {
                sig: sodium.to_hex(sodium.crypto_sign_detached(m.challenge, keys.privateKey)),
                pubkey: sodium.to_hex(keys.publicKey),
                timestamp: Math.floor(Date.now()/1000),
                challenge: m.challenge,
                type: 'helo'
            }

            console.log("sending response:")
            console.log(response)

            // start listening for stdin

            const rl = readline.createInterface({
                input: process.stdin,
                output: process.stdout
            });


            ws.on('message', (m)=>{
                console.log("received message: ---")
                console.log(m)
                console.log("---------------------")
            })
            ws.send(JSON.stringify(response))
            
            var f= ()=>{ rl.question('', (answer) => {
                    console.log("sending: " + answer)
                    ws.send(answer + "\n")
                    f()
                })}
            f()
        }
    })


}


