const sodium = require('libsodium-wrappers')
const fs = require('fs')
const HP_VERSION = 0.1

// sodium has a trigger when it's ready, we will wait and execute from there
sodium.ready.then(main).catch((e)=>{console.log(e)})

// datastructure representing all globals for this node
node = {}

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
        unl: [sodium.to_hex(keys.publicKey)]
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
 
    // todo: check state
    // todo: check history

    // execution to here = all config loaded successfully
}


// hotpocket controller entry point
function main() {

    // process cmdline if present
    process_cmdline(process.argv)

    // load config
    load_contract()
    
    // connect to peers
    open_peer_connections()


}
