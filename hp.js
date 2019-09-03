const HP_VERSION = 0.1
const fs = require('fs')
const ws_api = require('ws');
const sodium = require('libsodium-wrappers')
const crypto = require('crypto')


// sodium has a trigger when it's ready, we will wait and execute from there
sodium.ready.then(main).catch((e)=>{console.log(e)})

// datastructure representing all valid config for this node
node = {}

// namespace for all working variables
ram = {}


// first half of sha512 with t prepended before hashing
function SHA512H(m, t) {
    if (t == undefined) t = ''
    if (typeof(m) == 'object') m = JSON.stringify(m)
    m = t + '' + m
    return crypto.createHash('sha512').update(m).digest('hex').slice(0,16) 
}

// print a message to stdout then quit
function die(message, zero_exit) {
    if (message) console.log(message)
    process.exit(zero_exit ? 0 : 1)
}

// prints a warning
function warn(message) {
    console.log("WARN: " + message)
}

function process_cmdline(argv) {

    var flags = {}
    for (var i = 2; i < argv.length; ++i) {
        if (argv[i].slice(0,1) != '-') continue
        var trimflag = argv[i].replace(/^-*/, '').slice(0,1)
        if (trimflag == '') die('invalid flag ' + argv[i])
        flags[trimflag] = true
    }

    if (argv.length < 3 || flags.h || argv[2].slice(0,1) == '-')
        die(
            "usage: <contract-root-directory> [flags]\n" +
            "flags: \n" +
            "   -k  rekey an existing contract (e.g. this is a new node)\n" +
            "   -n  create new contract in the specified directory\n" +
            "   -h  this help message\n" +
            ""
        )
    
    node.dir = argv[2]
   
    if (flags.n) create_contract()
    else if (flags.k) rekey_contract()

}


function create_contract() {

    fs.mkdirSync(node.dir, '0711')
    fs.mkdirSync(node.dir + '/bin', '0711')
    fs.mkdirSync(node.dir + '/cfg', '0711')
    fs.mkdirSync(node.dir + '/hist', '0711')
    fs.mkdirSync(node.dir + '/state', '0711')

    var keys = sodium.crypto_sign_keypair()

    var config = { 
        hotpocket: '0.1',
        pubkey: sodium.to_hex(keys.publicKey),
        seckey: sodium.to_hex(keys.privateKey),
        keytype: keys.keyType,
        binary: 'bin/contract',
        peers: [],
        unl: [sodium.to_hex(keys.publicKey)],
        ip: '0.0.0.0',
        pubport: '8080',
        peerport: '22860',
        roundtime: '1000'
    }    

    fs.writeFileSync(node.dir + '/cfg/hp.cfg', JSON.stringify(config, null, 2))

    die('contract created at ' + node.dir, true)
}

function rekey_contract() {

    // load the config, we're just going to assume the rest of the contract structure is correct
    if (!fs.existsSync(node.dir + '/cfg')) die('contract config directory ' + node.dir + '/cfg not found')
    if (!fs.existsSync(node.dir + '/cfg/hp.cfg')) die('contract config file ' + node.dir + '/cfg/hp.cfg not found')
    var config = fs.readFileSync(node.dir + '/cfg/hp.cfg', 'utf8')
    try {
        config = JSON.parse(config)
    } catch (e) {
        console.log("invalid config while attempting rekey")
        die(e)
    }

    // generate new signing keys
    var keys = sodium.crypto_sign_keypair()
    config.pubkey = sodium.to_hex(keys.publicKey)
    config.seckey = sodium.to_hex(keys.privateKey)
    config.keytype = keys.keyType
    config.unl.push(config.pubkey)

    // write the new keys to the config
    fs.writeFileSync(node.dir + '/cfg/hp.cfg', JSON.stringify(config, null, 2))

    // done
    die('rekeyed the contract, you may want to ensure the UNL is correct', true)

}

function load_contract() {

    // first check all the directories exist
    if (!fs.existsSync(node.dir)) die('contract directory ' + node.dir + ' not found')
    if (!fs.existsSync(node.dir + '/bin')) die('contract binary directory ' + node.dir + '/bin not found')
    if (!fs.existsSync(node.dir + '/cfg')) die('contract config directory ' + node.dir + '/cfg not found')
    if (!fs.existsSync(node.dir + '/state')) die('contract state directory ' + node.dir + '/state not found')
    if (!fs.existsSync(node.dir + '/hist')) die('contract history directory ' + node.dir + '/hist not found')
    
    // now check for the config
    if (!fs.existsSync(node.dir + '/cfg/hp.cfg')) die('contract config file ' + node.dir + '/cfg/hp.cfg not found')

    // load the config and confirm it is valid json
    var config = fs.readFileSync(node.dir + '/cfg/hp.cfg', 'utf8')

    try {
        config = JSON.parse(config)
    } catch (e) {
        console.log("invalid config")
        die(e)
    }

    // check version
    if (!config.hotpocket) die('contract config is missing version information / might not be a hp config file')
    if (config.hotpocket > HP_VERSION) die('contract config is for a newer version of hotpocket, please upgrade') 

    // load keys
    if (!config.pubkey) die('contract config is missing public key')
    if (!config.seckey) die('contract config is missing secret key')
    if (!config.keytype) die('contract config is missing keytype')   
    if (config.keytype != 'ed25519') die('this version of hotpocket only supports ed25519 keys')

    node.pk = Buffer.from(config.pubkey, 'hex')
    node.sk = Buffer.from(config.seckey, 'hex')

    // check the keys work
    var sig = sodium.crypto_sign('test', node.sk)
    if (new TextDecoder("utf-8").decode(sodium.crypto_sign_open(sig, node.pk)) != 'test')
        die('contract config public and private keys do not match or are invalid or corrupt') 

    // check the binary exists and executes
    if (!config.binary) die('contract binary must be specified in the config file e.g. { ..., "binary": "bin/contract" }')
    if (!fs.existsSync(node.dir + '/' + config.binary)) die('contract binary not found at ' + node.dir + '/' + config.binary)
    node.binary = config.binary

    // check peer array
    if (typeof(config.peers) != 'object' || typeof(config.peers.length) != 'number')
        die('contract config lacks valid peers array e.g. "peers": ["127.0.0.1:10001", ...]')
    
    // parse peer array
    node.peers = []
    for (var i in config.peers)
        node.peers.push({
            ip: config.peers.replace(/:.+$/,''),
            port: config.peers.replace(/^.*?:/,'')
        })
    
    if (node.peers.length == 0)
        warn('no peers specified, this contract will execute only on this node')


    // check unl array
    if (typeof(config.unl) != 'object' || typeof(config.unl.length) != 'number')
        die('contract config lacks valid unrl array e.g. "unl": ["<hexpublickey1>", ...]')
 
    // check unl
    if (config.unl.length == 0)
        die('no UNL specified, at minimum this node must trust itself, try: "unl": ["'+config.pubkey+'"]')    
  
    // check our public key is in the UNL
    var pk_in_unl = false
    for (var i in config.unl) 
        if (config.unl[i] == config.pubkey) {
            pk_in_unl = true
            break
        }
    if (!pk_in_unl)
        die('this node\'s public key was not present in its UNL, try: "unl": ["'+config.pubkey+'"]')

    // parse UNL keys
    node.unl = []
    for (var i in config.unl)
        node.unl.push(Buffer.from(config.unl[i], 'hex'))

    // check ip
    if (!config.ip || !config.ip.match(/[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/))
        die(
            'contract config does not specify ip to bind to or specified ip is invalid,\n' + 
            'try "ip": "0.0.0.0" to bind all interfaces'
        )
    node.ip = config.ip
 
    // check ports
    if (!config.peerport) die('contract config must specify peer port, try: "peerport": 22860')
    if (!config.pubport) warn('contract config does not specify a public port, the public will not have access')

    if (config.pubport) node.pubport = config.pubport
    node.peerport = config.peerport

    // todo: check state
    // todo: check history

    // execution to here = all config loaded successfully
}

function open_listen() {
    ram.peer_server = new ws_api.Server({ port: node.peerport });
    if (node.pubport) ram.public_server = new ws_api.Server({ port: node.pubport });

    ram.peer_server.on('connection', on_peer_connection)
    if (node.pubport) ram.public_server.on('connection', on_public_connection)

    ram.peer_connections = {}
    ram.public_connections = {}

    // contains a dict comprising SHA512H -> time received
    ram.recent_peer_msghash = {}
}


function on_peer_connection(ws) {
    //todo: filter to by ip ensure peer is on peer list
    ws.on('message', on_peer_message)
}

function on_public_connection(ws) {
    if (!node.pubport) die('received a public connection even though public port was not specified')
    //todo: filter by abuse/ip here to stop ddos
    ws.on('message', on_public_message)
}

function on_peer_message(message) {
    var time = Date.now()

    // convert the message to json
    // this is cheap so do this first
    var msg = {}
    try {
        msg = JSON.parse(message)
    } catch(e) {
        //todo: disconnect peer for sending bad messages here
        warn('bad message from peer')
        return
    }
    
    
    // check if the peer is on our UNL
    // this is also pretty cheap so do this second
    var valid_peer = false
    if (msg.pubkey)
    for (var i in node.unl)
        if (msg.pubkey == node.unl[i]) {
            valid_peer = true
            break
        }
    
    if (!valid_peer) {
        warn('received peer message from peer not on our UNL')
        //todo: block non-unl peers
        return
    }
   
    // check timestamp on message 
    if (msg.timestamp < time/1000.0 - node.roundtime * 4)
        return warn('received message from peer but it was old')

    // if the message is valid json and has a pub key we'll hash it and check if we've seen it before
    // but first we need to prune the signature from it
    var sig = msg.sig
    delete msg.sig
    var msgnosig = JSON.stringify(msg, Object.keys(msg).sort())
    // todo: check for further malleability attacks here
    var msghash = SHA512H(msgnosig, 'PEERMSG')
    
    // check if we've seen this message before
    if (ram.recent_peer_msghash.msghash) return

    // place an entry into the cache
    ram.recent_peer_msghash[msghash] = time

    // prune old message hash cache
    // todo: put this on a timer for much better performance
    for (var i in ram.recent_peer_msghash)
        if (ram.recent_peer_msghash[i] < time - 60)
            delete ram.recent_peer_msghash[i]


    // check the signature 
    // this is pretty expensive
    if (!sodium.crypto_sign_verify_detached(sig, msgnosig, Buffer.from(msg.pubkey, 'hex')))
        return warn('received bad signature from peer') // todo: punish peer

    // execution to here is a valid peer message

    // check what sort of message it is
    if (msg.type == 'proposal') {
        ram.proposals[msghash] = msg.proposal
    } 

}

function on_public_message(message) {
    var msghash = SHA512H(message, 'PUBMSG')

}

// hotpocket controller entry point
function main() {

    // process cmdline if present
    process_cmdline(process.argv)

    // load config
    load_contract()
   
    // start listening for peers
    open_listen()
 
    // connect to peers
    open_peer_connections()


}
