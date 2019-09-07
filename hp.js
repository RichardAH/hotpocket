const HP_VERSION = 0.1
const fs = require('fs')
const ws_api = require('ws');
const sodium = require('libsodium-wrappers')
const crypto = require('crypto')
const pipe = require('posix-pipe-fork-exec')
const readline = require('readline')


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
    return crypto.createHash('sha512').update(m).digest('hex').slice(0,64) 
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

// helper from https://stackoverflow.com/questions/56134298/is-there-a-way-to-get-all-keys-inside-of-an-object-including-sub-objects
const get_all_keys = obj => Object.keys(obj).flatMap(k => Object(obj[k]) === obj[k] ? [k, ...get_all_keys(obj[k])] : k).sort()

function key_of_highest_value(obj) {
    var highestval = Math.max(...Object.values(obj))

    for (var i in obj) 
        if (obj[i] == highestval) return i

    return null
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
    
    node.dir = argv[2].replace(/\/+$/, '')
    
   
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
        binargs: '',
        peers: [],
        unl: [sodium.to_hex(keys.publicKey)],
        ip: '0.0.0.0',
        peerport: '22860',
        roundtime: '1000',
        pubport: '8080',
        pubmaxsize: '65536',
        pubmaxcpm: '100'
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

    // these are buffer/array keys
    node.pubkeybuf = Buffer.from(config.pubkey, 'hex')
    node.seckeybuf = Buffer.from(config.seckey, 'hex')

    // these are the hex encoded versions to save converting between
    node.pubkeyhex = config.pubkey
    node.seckeyhex = config.seckey

    // check the keys work
    var sig = sodium.crypto_sign('test', node.seckeybuf)
    if (new TextDecoder("utf-8").decode(sodium.crypto_sign_open(sig, node.pubkeybuf)) != 'test')
        die('contract config public and private keys do not match or are invalid or corrupt') 

    // check the binary exists and executes
    if (!config.binary) die('contract binary must be specified in the config file e.g. { ..., "binary": "bin/contract" }')
    if (!fs.existsSync(node.dir + '/' + config.binary)) die('contract binary not found at ' + node.dir + '/' + config.binary)
    node.binary = config.binary

    // check if bin args are specified
    node.binargs = ( config.binargs ? config.binargs.split(' ') : [] )
    

    // check peer array
    if (typeof(config.peers) != 'object' || typeof(config.peers.length) != 'number')
        die('contract config lacks valid peers array e.g. "peers": ["127.0.0.1:10001", ...]')
    
    // parse peer array
    node.peers = []
    for (var i in config.peers)
        node.peers.push({
            ip: config.peers[i].replace(/:.+$/,''),
            port: config.peers[i].replace(/^.*?:/,'')
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
        node.unl.push( { buf: Buffer.from(config.unl[i], 'hex'), hex: config.unl[i] })

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

    // check roundtime
    if (!config.roundtime) die('must specify contract roundtime, try: "roundtime": "1000"')
    node.roundtime = parseInt('' + config.roundtime, 10)
    if (node.roundtime <= 0) die('round time must be >= 1 ms')

    // some public rate and size limits might be specified
    if (config.pubmaxcpm) node.pubmaxcpm = config.pubmaxcpm
    if (config.pubmaxsize) node.pubmaxsize = config.pubmaxsize

    // check history
    // hist/ directory consists of json files (ledgers) named by their lcl hash
    // we'll scan the directory for the newest file and load that as the lcl

    var newest_mtime = 0
    var history_files = fs.readdirSync(node.dir + '/hist')

    // this will map lcl -> llcl, however it will be inverted copied to ram.consensus.ledger_history
    var history_map = {}

    for (var file in history_files) {

        // check if valid hex
        if (!history_files[file].match(/^[0-9a-f]{64}/)) {
            die('found ' + history_files[file] + ' in ' + node.dir + '/hist, however this is not a valid history filename')
        }

        // check if valid file
        var stat = {}
        try {
            stat = fs.statSync(node.dir + '/hist/' + history_files[file])
        } catch (e) {
            die('history file could not be read ' + node.dir + '/hist/' + history_files[file])
        }

        if (stat.isDirectory()) 
            die('found directory in ' + node.dir + '/hist, there should be no folders in this directory')
     
        // check if valid json 
        var json = {}
        var raw = ""
        try {
            json = JSON.parse(raw = fs.readFileSync(node.dir + '/hist/' + history_files[file]).toString())
        } catch (e) {
            die('could not read or parse ' + node.dir + '/hist/' + history_files[file])    
        }

        // check if valid hash (expensive)
        var hash = SHA512H(raw, 'LEDGER')
        if (hash != history_files[file]) 
            die('history file ' + node.dir + '/hist/' + history_files[file] + ' content does not match declared hash')
        
        // map the lcl -> llcl
        history_map[history_files[file]] = json.lcl
        
        // check if last closed ledger that we have access to
        if (stat.mtimeMs > newest_mtime) {
            newest_mtime  = stat.mtimeMs
            // the last closed ledger will be the newest in the directory
            // if the network is ahead of us we'll learn about that after 
            // we begin participating. if there are no valid history files
            // then the ram initialisation routine has set the first lcl
            // to "genesis" already and this code will not be executed.
            ram.consensus.lcl = history_files[file]
        }
    }

    // convert to llcl -> lcl
    ram.consensus.ledger_history = swap_keys_for_values(history_map) 

    // todo: check state

    // execution to here = all config loaded successfully
}

/**
    Open websocket ports for listening based on config
    NB: TLS implementation needed
**/
function open_listen() {
    ram.peer_server = new ws_api.Server({ port: node.peerport });
    ram.peer_server.on('connection', on_peer_connection)
    ram.peer_server.on('close', on_peer_close)

    var ws_self = new ws_api('ws://0.0.0.0:'+node.peerport)
    ws_self._self = true
    ws_self.on('open',((w)=>{return ()=>{on_peer_connection(w)}})(ws_self))        
    
    if (node.pubport) {
        ram.public_server = new ws_api.Server({ port: node.pubport });
        ram.public_server.on('connection', on_public_connection)
        ram.public_server.on('close', on_public_close)
    }

}

// scans peers continuously attempting to maintain peer connections if they drop
function peer_connection_watchdog() {
    // create a list of IPs we should have active connections with
    var peer_ips = {}
    for (var i in node.peers)
        peer_ips[node.peers[i].ip] = node.peers[i].port

    // delete from that list every IP we do already have an active connection with
    for (var i in ram.peer_connections) {
        var ip = i.replace(/:.+$/,'')
        if (peer_ips[ip]) delete peer_ips[ip]
    } 

    // finally attempt new connections to anyone left on the list
    for (var i in peer_ips) {
        var ws = false
        var url = 'ws://' + i + ':' + peer_ips[i]
        try {
            ws = new ws_api(url)
            ws.on('error', e=>{
                warn('attempted to connect to peer ' + i + ':' + peer_ips[i] + ' but could not connect')
                warn(e)
            })
            ws.on('open',((w)=>{return ()=>{on_peer_connection(w)}})(ws))        
        } catch (e) {
            warn('attempted to connect to peer ' + i + ':' + peer_ips[i] + ' but could not connect')
        }
    }
    
    setTimeout(peer_connection_watchdog, node.roundtime*4)
}

function on_peer_close(ws) {
    for (var i in ram.peer_connections)
        if (ram.peer_connections[i] == ws) {
            delete ram.peer_connections[i]
            return
        }
}

function on_public_close(ws) {
    for (var i in ram.public_connections_authed)
        if (ram.public_connections_authed[i] == ws) {
            delete ram.public_connections_authed[i]
            return
        }

    for (var i in ram.public_connections_unauthed)
        if (ram.public_connections_unauthed[i] == ws) {
            delete ram.public_connections_unauthed[i]
            return
        }
}


//todo: handle public disconnection


function on_public_connection(ws) {

    if (!node.pubport) die('received a public connection even though public port was not specified')
    //todo: filter by abuse/ip here to stop ddos
    ram.public_connections_unauthed[ws._socket.remoteAddress + ":" + ws._socket.remotePort] = ws
    var challenge = sodium.to_hex(sodium.randombytes_buf(16))
    ws.send(JSON.stringify({
        hotpocket: HP_VERSION,
        type: "public_challenge",
        challenge: challenge
    }))
    ws._challenge = challenge

    ws.on('close', () => {

        if (ws._authed) {
            delete ram.public_connections_authed[ws._authed]
            return
        }

        delete ram.public_connections_unauthed[ws._socket.remoteAddress + ":" + ws._socket.remotePort]

    })
 
    ws.on('message', (message) => {

        // this handles authorized transactions
        if (ws._authed) {

            ws._msgcount++
            if (message.length > node.pubmaxsize) return warn('received oversized authed public message')
            if ((Date.now()/1000 - ws._start) / ws._msgcount > node.pubmaxcpm) return warn('received too many messages from authed public user: '+ ws._msgcount + " time alive: " + (Date.now()/1000 - ws._start))
            if (!ws._authed) return warn('received authed message from a websocket without an _authed prop')
            if (!ram.local_pending_inputs[ws._authed]) ram.local_pending_inputs[ws._authed] = []
            ram.local_pending_inputs[ws._authed].push(message)
            
            return
        }

        // all we want here is an auth message, once they have managed that
        // we'll move them to the public authed group

        // todo: punish all invalid messages 
        
        // first see if the message is json
        var msg = {}
        try {
            msg = JSON.parse(message)
        } catch (e) {
            // message isn't json just return
            return
        }

        // we're expecting a message with type = helo
        if (msg.type != 'helo')
            return warn('unauthed public node sent message other than helo')

        if (!msg.sig || !msg.timestamp)
            return warn('unauthed public node sent message missing sig or timestamp')

        if (msg.challenge != ws._challenge)
            return warn('unauthed public node sent message lacking challenge response')
        
        if (!msg.pubkey)
            return warn('unauthed public node sent message lacking pub key')

        try {
            if (!sodium.crypto_sign_verify_detached(Buffer.from(msg.sig, 'hex'), msg.challenge, 
                    Buffer.from(msg.pubkey, 'hex'))
                ) throw null
        } catch (e) {
            if (e) warn(e)
            return warn('received bad signature from unauthed pub node ')
        }
        // execution to here means the node has authed
        delete ram.public_connections_unauthed[ws._socket.remoteAddress + ":" + ws._socket.remotePort]
        var authed = ws._socket.remoteAddress + ":" + ws._socket.remotePort + ";" + msg.pubkey
        ram.public_connections_authed[authed] = ws
        ram.local_pending_inputs[authed] = []
        
        // record the key in the socket for future use
        ws._authed = authed
        ws._pubkey = msg.pubkey
        ws._start = Date.now()/1000
        ws._msgcount = 0

        dbg(ws._pubkey + " was authed")

    })
}


function prune_cache_watchdog() {

    var time = Date.now()
    for (var i in ram.recent_peer_msghash)
        if (ram.recent_peer_msghash[i] < time - 60)
            delete ram.recent_peer_msghash[i]

    setTimeout(prune_cache_watchdog, 60)

}


function on_peer_connection(ws) {
    //todo: filter to by ip ensure peer is on peer list
    ram.peer_connections[ws._socket.remoteAddress + ":" + ws._socket.remotePort] = ws
    ws.on('message', (message)=> {

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
        for (var i in node.unl) {
            if (msg.pubkey == node.unl[i].hex) {
                valid_peer = true
                break
            }
        }
        
        if (!valid_peer) {
            warn('received peer message from peer not on our UNL pk = ' + msg.pubkey)
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
        var msgnosig = JSON.stringify(msg, get_all_keys(msg))


        // todo: check for further malleability attacks here
        var msghash = SHA512H(msgnosig, 'PEERMSG')

        // check if we've seen this message before
        if (ram.recent_peer_msghash[msghash]) return

        // place an entry into the cache
        ram.recent_peer_msghash[msghash] = time


        // check the signature 
        // this is pretty expensive
        try {
            if (!sodium.crypto_sign_verify_detached(Buffer.from(sig, 'hex'), msgnosig, Buffer.from(msg.pubkey, 'hex')))
                throw null
        } catch(e) {
            if (e) warn(e)
            return warn('received bad signature from peer') // todo: punish peer
        }
        // execution to here is a valid peer message

        // check what sort of message it is
        if (msg.type == 'proposal' && contains_keys(msg, 'con', 'inp', 'out', 'lcl', 'stage', 'timestamp', 'type')) {
            console.log('received proposal')
            ram.consensus.proposals[msghash] = msg
            // broadcast it to our peers
            broadcast_to_peers(message)
        } else if (msg.type == 'hist_req' && contains_keys(msg, 'lcl')) {
            // a history request message specifies the last closed ledger that the peer knew of
            // this node will retreive that ledger if it can and all newer ledgers it has and send these

            var response = {
                type: "hist_resp",
                hist: {}
            }

            var requested_lcl = '' + msg.lcl
            if (!requested_lcl.match(/^[0-9a-f]{64}$/)) {
                return warn('received history request but lcl was invalid hex')
                //todo: penalise peer
            }

            // defensively restrict what the lcl can be even though we checked it above, because it's about
            // to be fed into the file system
            
            if (requested_lcl != 'genesis')
                requested_lcl = ('' + requested_lcl).replace(/^[^a-f0-9]$/, '')


            // history_map maps a last closed ledger to the ledger closed before that one lcl => llcl
            // however after we build this map we will flip it so llcl->lcl
            var history_map = {}

            // this will just keep a memory version of the history files we read so we can send them to the recepient
            var history_raw = {}

            // todo: prune history aggressively to avoid crashing due to memory constraints

            var history_files = fs.readdirSync(node.dir + '/hist')
            for (var file in history_files) {
                var json = ""
                var raw = ""
                try {
                    json = JSON.parse(raw = fs.readFileSync( node.dir + '/hist/' + requested_lcl).toString())
                } catch (e)  {
                    warn('attempted to read history file ' + history_files[file] + ' but it didn\'t exist or wasn\'t valid JSON')
                    continue
                }           

                history_map[history_files[file]] = json.lcl
                history_raw[history_files[file]] = raw
            }

            // swap keys with values in the history map
            history_map = swap_keys_for_values(history_map)
            
            // now history_map is llcl -> lcl

            while (history_map[requested_lcl]) {
                // we found the history they were after, so attach it to the response and then 
                // check if there's another ledger after the one we found
                response.hist[requested_lcl] = history_raw[requested_lcl]

                // fetch the next in the sequence
                requested_lcl = history_map[requested_lcl]
            } 

            // send any fetched history to the peer
            return ws.send(sign_peer_message(response).signed)

        } else if (msg.type == 'hist_resp' && contains_keys(msg, 'hist_resp')) {

            // first check if we actually asked anyone for history!
            if (!ram.consensus.last_history_request)
                return warn('peer sent us a history response but we never asked for one!')
            //todo: consider punishing peer here

            if (!(ram.consensus.last_history_request in msg.hist)) 
                return warn('peer send us a history response but not containing the lcl we asked for!')
            //todo: consider punishing peer here
         
            // execution to here means we received history containing the lcl we've requested

            // clear the last requested variable
            var requested_lcl = ram.consensus.last_history_request
            ram.consensus.last_history_request = false

            // build history map llcl->lcl
            received_history_map = {}
            received_history = {} // contains unhexed object of each ledger
            received_history_raw = {}
            for (var lcl in msg.hist) {
                try {
                    received_history[lcl] = JSON.parse(received_history_raw[lcl] = Buffer.from(msg.hist[lcl], 'hex').toString()) 
                    received_history_map[lcl] = received_history[lcl].lcl
                } catch(e) {
                    return warn('peer send us a history response which we asked for but contained invalid history ... hex or json would not parse')
                }

            }
  
            // invert the map such that llcl -> lcl
            received_history_map = swap_keys_for_values(received_history_map)

            // start at the first requested ledger and track forward, checking integrity as we go
            var newest_lcl = ""
            var upto_lcl = requested_lcl
            while (upto_lcl in received_history_map) {
                // check the integrity of the data                
                var hash = SHA512H(received_history_raw[upto_lcl], 'LEDGER')
                if (hash != upto_lcl)
                    return warn('peer sent us a history response we asked for but the ledger data does not match the ledger hashes')

                upto_lcl = received_history_map[upto_lcl]
                newest_lcl = upto_lcl
            }
            // execution to here means the history data sent checks out, so incorporate it

            // first set the last closed legder to the most receive history we received
            ram.consensus.lcl = upto_lcl

            // now back fill our history cache
            for (var i in received_history_map) 
                ram.consensus.ledger_history[i] = received_history[i]
            
            // finally write files, we do this as two seperate loops because file writing is slow!
            // and consensus needs to get under way!!
            for (var i in received_history_map) 
                fs.writeFileSync(node.dir + '/hist/' + i, received_history_raw[i])

            // done!!!

        } else warn('received invalid message from peer') 

    })
}

function sign_peer_message(message) {
    // ensure the message contains a timestamp and public key, add one if it doesnt
    if (!('timestamp' in message)) message.timestamp = Math.floor(Date.now()/1000)
    if (!('pubkey' in message)) message.pubkey = node.pubkeyhex


    // to sign we need to first JSON stringify it in a key sorted fashion
    var msg_unsigned = JSON.stringify(message, get_all_keys(message))

    // create the signature
    var sig = sodium.to_hex(sodium.crypto_sign_detached(msg_unsigned, node.seckeybuf))

    // then add the signature to the message and stringify it again
    message.sig = sig
    var msg_signed = JSON.stringify(message, get_all_keys(message))

    return  { signed: msg_signed, unsigned: msg_unsigned }
}


function broadcast_to_peers(message) {
    for (var i in ram.peer_connections)
        try {
            ram.peer_connections[i].send(message)
        } catch (e) {
            // peer isn't ready probably
            // todo: prune dead peers here
        }
}

function send_to_random_peer(message) {
    var peer_keys = Object.keys(ram.peer_connections)

    // we might be the only peer
    if (peer_keys.length == 1) 
        return false

    // attempt up to 10 times to randomly find and send to a peer
    var attempts = 0
    while(attempts++ < 10) {
        peer = peer_keys[sodium.randombytes_buf(1)[0] % peer_keys.length]
        if (ram.peer_connections[peer]._self) continue

        try {
            ram.peer_connections[peer].send(message)
        } catch (e) {}

        return true
    }

    return false
}



// helpers

function dbg(m, o) {
    if (typeof(o) != 'undefined') {
        console.log('DBG: ' + m)
        var out = JSON.stringify(o, null, 2)
        var lines = out.split('\n')
        for (var i in lines) console.log('     ' + lines[i])
    } else console.log('DBG: ' + m)
}

// helper function for voting
function inc(x, y) { if (x[y] == undefined) return x[y] = 1; return x[y]++; }

function  contains_keys (obj, ...key_set) {
	for (var x in key_set) 
		if (!(key_set[x] in obj)) return false	
	return true
}

// key swap code from https://stackoverflow.com/a/46582758
// swap the keys and values in an object
function swap_keys_for_values(dict) {
    return Object.assign({}, ...Object.entries(dict).map(([a,b]) => ({ [b]: a })))
}

function wait_for_proposals(reset) {
    if (reset) ram.consensus.stage = 0
    ram.consensus.nextsleep = (sodium.randombytes_buf(1)[0]/256) * node.roundtime 
}

/**
    Check our LCL is consistent with the proposals being made by our UNL peers
    lcl_votes -- dictionary mapping lcl -> number of peers who proposed for that lcl
    return value: true if proposing should stop for history catch up, 
                  false if proposing should continue
**/
function check_lcl_votes(lcl_votes) {

    var total_votes = 0 
    for (var i in lcl_votes)
            total_votes += lcl_votes[i]
    
    if (total_votes == 0)
        return true 

    if (total_votes < node.unl.length * 0.8) {
            warn('not enough peers proposing to perform consensus (' + total_votes + ' out of ' + node.unl.length + 
                 ', need ' + Math.ceil(node.unl.length*0.8) + ')')
            return false
    }

    var winning_lcl = key_of_highest_value(lcl_votes)

    var winning_votes = lcl_votes[winning_lcl]

    if ( winning_votes / total_votes < 0.8) 
    {
        // fork condition
        die('no consensus on lcl, fatal. votes were: ' + JSON.stringify(lcl_votes)) 
    }

    // execution to here means the winning_lcl has 80%+ support

    if (ram.consensus.lcl != proposal.lcl) {

        // create a history request
        request = {
            type: "hist_req",
            lcl: winning_lcl
        }
        
        ram.consensus.last_history_request = winning_lcl

        var signed_history_request = sign_peer_message(request).signed
        
        send_to_random_peer(signed_history_request) 

        warn('we are not on the consensus ledger, requesting history from a random peer')

        return true
        //todo: catch up state
    }

    return false
}
/** 
    Execute a consensus round 
**/
function consensus() {

    // wait for entry point into consensus cycles
    var time = (+ new Date())


    /**
        A proposal is a json object consisting of 5 sections
        Connections (for this round)
            only include connections we have directly in stage 0
        Inputs      (for this round)
            only include inputs we have directly in stage 0
        Outputs     (from last round)
            only include outputs we have directly in stage 0
        State       (from last round)
        LastCloseed (from last round)
    **/

    proposal = {
        hotpocket: HP_VERSION,
        type: 'proposal',
        pubkey: node.pubkeyhex,
        timestamp: time,
        con: [],
        inp: [],
        out: [],
        sta: "",
        lcl: ram.consensus.lcl,
        stage: ram.consensus.stage
    }


    switch(ram.consensus.stage) {

        case 0: // in stage 0 we create a novel proposal and broadcast it
        {
            
            var pending_inputs = ram.local_pending_inputs
            ram.local_pending_inputs = {}


            // clear out the old stage 3 proposals and any previous proposals made by us
            // todo: check the state of these to ensure we're running consensus ledger
            for (var p in ram.consensus.proposals) {
                if (ram.consensus.proposals[p].stage == 3 || ram.consensus.proposals[p].pubkey == node.pubkeyhex)
                    delete ram.consensus.proposals[p] 
            }

            // change inp and out to objects for stage 0
            // once full versions of inputs and outputs have been circulated
            // only their hashes are voted upon, and these are kept in arrays
            // for the avoidance of doubt: stage 0 proposals have inp, out as objects
            // mapping user_public_key_hex -> [an array of the user's inputs]
            // stage 1..3 proposals have an array e.g.
            // inp = [ hash_of_user_1_inputs, hash_of_user_2_inputs, .. ]
            proposal.inp = {}
            proposal.out = {}


            for (var i in ram.public_connections_authed) {
                // add all the connections we host (mentioned by their public key only)
                var user = i.replace(/^.+;/,'')
                proposal.con.push(user)

                // and all their pending messages
                if (pending_inputs[i] && pending_inputs[i].length > 0) {

                    proposal.inp[user] = []
                    for (var j in pending_inputs[i]) {
                        var user_input = pending_inputs[i][j]
                        proposal.inp[user].push(sodium.to_hex(user_input)) //push(user_input)
 
                        //todo: old inputs need to be stripped from this object when consensus round closes
                        //any that didn't make it into the Nth round need to make it into N+1
                        if (!ram.local_pending_inputs_old[i]) ram.local_pending_inputs_old[i] = []
                        ram.local_pending_inputs_old[i].push(user_input)
                    }
                }
            }

            // propose outputs from previous round if any
            for (var user in ram.consensus.local_output_dict) 
                proposal.out[user] = ram.consensus.local_output_dict[user]
            

            // todo: gather and propose state
            // todo: gather and propose lcl

            dbg("novel prop" , proposal)

            broadcast_to_peers(sign_peer_message(proposal).signed)

            break
        }

        case 1:
        case 2:
        case 3:
    
            var proposals = ram.consensus.proposals
            

            ram.consensus.proposals = {}

            
            var votes = {
                con: {},
                inp: {},
                out: {},
                sta: {},
                lcl: {},
                stage: {} // this will let us know if we're participating properly in consensus
            }

            // we need to consider what our peers believe the LCL is first before we can participate in voting
            // if our peers have different ideas of what the LCL is we might be in a fork condition
            // and need to halt, alternatively if > 80% agree on an LCL different to ours we need to request
            // history first and are not currently ready to vote

            lcl_votes = {}
            for (var i in proposals)
                if (time - proposals[i].timestamp < node.roundtime * 4 && 
                    proposals[i].stage == ram.consensus.stage - 1) {
                    inc(lcl_votes, proposals[i].lcl)
                } else if (proposals[i].stage < ram.consensus.stage - 1) {
                    console.log("deleting old proposals " + proposals[i].lcl + ".stage=" + 
                                proposals[i].stage + " from " + proposals[i].pubkey)
                    delete proposals[i]
                }

            if (check_lcl_votes(lcl_votes))
                return wait_for_proposals(true)

            // execution to here means we are on the consensus ledger

            for (var i in proposals) {
                var p = proposals[i]

                dbg('proposal ' + i, proposals[i])
            
                inc(votes.sta, p.sta)
   
                // todo: no real need for either of these, consider removing
                inc(votes.lcl, p.lcl)
                inc(votes.stage, p.stage)

                for (var j in p.con)
                    inc(votes.con, p.con[j])
   
                for (var j in p.inp) {
                    // inputs are processed as a hash of the JSON of the proposed input
                    var hash = ""
                    if (typeof(p.inp[j]) == "object") {
                        // this is a full input proposal, so we need to hash it
                        var possible_input = {}
                        possible_input[j] = p.inp[j]
                        hash = SHA512H(JSON.stringify(possible_input), 'INPUT')
                        ram.consensus.possible_input_dict[hash] = possible_input

                    } else {
                        // this is already a hash
                        hash = p.inp[j]
                    }

                    inc(votes.inp, hash)
                }

                // repeat above for outputs
                for (var j in p.out) {
                    // inputs are processed as a hash of the JSON of the proposed input
                    var hash = ""
                    if (typeof(p.out[j]) == "object") {
                        // this is a full output proposal, so we need to hash it

                        dbg("p.out[j] = ", p.out[j])
                        var possible_output = {}
                        possible_output[j] = p.out[j]
                        hash = SHA512H(JSON.stringify(possible_output), 'OUTPUT')
                        ram.consensus.possible_output_dict[hash] = possible_output
                    } else {
                        // this is already a hash
                        hash = p.out[j]
                    }

                    inc(votes.out, hash)
                }

            }

            // voting is according to specific rules
            var total_votes = Object.keys(proposals).length
            var total_possible_votes = node.unl.length

            // firstly 80% of our peers must be online and voting before we will progress 
            if (total_votes / total_possible_votes < 0.8) {
                warn('will not proceed until 80% of UNL peers are proposing -- have ' + total_votes + ' out of ' + total_possible_votes)
                // copy proposals back into ram
                for (var i in proposals)
                    ram.consensus.proposals[i] = proposals[i] 
                return wait_for_proposals(false) 
            }



            // threshold the votes and build a new proposal
            var vote_threshold = ( ram.consensus.stage == 1 ? 0.50 * node.unl.length : 
                                 ( ram.consensus.stage == 2 ? 0.65 * node.unl.length :
                                 ( ram.consensus.stage == 3 ? 0.80 * node.unl.length : -1 )))



            for (var i in votes.con)
                if (votes.con[i] >= vote_threshold)
                    proposal.con.push(i)

            for (var i in votes.inp)
                if (votes.inp[i] >= vote_threshold)
                    proposal.inp.push(i)

            for (var i in votes.out)
                if (votes.out[i] >= vote_threshold)
                    proposal.out.push(i)

            var largest_count = 0 
            for (var i in votes.sta)
                if (votes.sta[i] > largest_count) {
                    proposal.sta = i
                    largest_count = votes.sta[i]
                }

            largest_count = 0 
            for (var i in votes.lcl)
                if (votes.lcl[i] > largest_count) {
                    proposal.lcl = i
                    largest_count = votes.lcl[i]
                }



            // todo: the way lcl and state are negotitated using a simple threshold is probably wrong
            // and will potentially lead to forks, should be reconsidered at a later date, e.g. prod

            var peer_msg = sign_peer_message(proposal)
            var proposal_msg_unsigned = peer_msg.unsigned

            // finally send the proposal to peers
            broadcast_to_peers(peer_msg.signed) 



            if (ram.consensus.stage == 3) {
                // we've reached the end of a consensus round

                // so we need to apply inputs, collect outputs
                // and clear buffers, and assign unused inputs to next round

                // here ledger is the encoded string version of the closed ledger,
                // proposal is the object form
                

                // prune off timestamp, pubkey, signature
                delete proposal.pubkey
                delete proposal.timestamp
                delete proposal.sig

                var ledger = JSON.stringify(proposal, get_all_keys(proposal))

                // lcl = last closed ledger
                var lcl = SHA512H( ledger, 'LEDGER' )
            
                console.log("trying to write lcl: " + node.dir + '/hist/' + lcl)
            
                fs.writeFileSync( node.dir + '/hist/' + lcl, ledger )

                ram.consensus.lcl = lcl


                // first send out any relevant output from the previous consensus round and execution
                for (var i in proposal.out) {
                    var hash = proposal.out[i]

                    if (!ram.consensus.possible_output_dict[hash]) {
                        warn('output required ' + hash + ' but wasn\'t in our possible output dict, this will potentially cause desync')
                        continue // todo: consider fatal
                    }



                    for (var user in ram.consensus.possible_output_dict[hash]) {
                        // there'll be just the one key

                        var output = ram.consensus.possible_output_dict[hash][user]
                        try {
                            output = Buffer.from(''+output, 'hex').toString()
                        } catch (e) {
                            warn('output represented by hash ' + hash + ' for user ' + user + ' was not valid hex') 
                            continue
                        } 

                        // check if the user is in our locally connected users
                        for (var j in ram.public_connections_authed) {
                            if (j.replace(/^.*;/, '') == user) {
                                // this is our locally connected user, send his contract output to him
                                ram.public_connections_authed[j].send(output)//Uint8Array.from(Buffer.from(output, 'hex')))
                                break
                            }
                        }
                    }
                }

                // now we can safely clear our output dictionary
                ram.consensus.possible_output_dict = {}


                // structure we need to provide to the contract binary run routine:
                // { user_pub_key: [ stream of raw input or empty if no input is available ] }
                // every connected user must have an entry

                dbg("stage 3 prop", proposal)

                var concrete_inputs = {}

                // we need to provide a dummy entry for every connected user
                // this is so the contract can push data to the user
                for (var i in proposal.con)
                    concrete_inputs[proposal.con[i]] = []

                // now process any actual inputs
                for (var i in proposal.inp) {
                    var hash = proposal.inp[i]
                    if (!ram.consensus.possible_input_dict[hash]) {
                        warn('input required ' + hash + ' but it wasn\'t in our possible input dict, this will cause desync')
                        continue //todo: consider making this fatal
                    }

                    for (var j in ram.consensus.possible_input_dict[hash]) {
                        // there'll be just the one key
                        var inputshex = ram.consensus.possible_input_dict[hash][j]
                        var inputsbuf = []
                        for (var k in inputshex)
                            inputsbuf[k] = Buffer.from(inputshex[k], 'hex')
                        
                        concrete_inputs[j] = inputsbuf
                        break
                    }
                }

                // clear possible input dictionary since we've materalised the actual inputs
                ram.consensus.possible_input_dict = {}

                //todo: check contract state against consensus
                //todo: check lcl against consensus


                // this will gather outputs into the appropriate place as they become available
                //todo: finish
                run_contract_binary(concrete_inputs)




        }
            
    }


    ram.consensus.stage = (ram.consensus.stage + 1) % 4  
}

function run_contract_binary(inputs) {

    var childpipesflat  = []     // pipes.childread, pipes.childwrite ]
    var parentpipesflat = []    // pipes.parentread, pipes.parentwrite ]

    // pubkeyhex -> {parentwrite:, parentread:} 
    var outputpipes = {}

    var fdlist = "HOTPOCKET " + HP_VERSION + "\n"


    for (var user in inputs) {
        var pipes = pipe.PipeDuplex()
        
        childpipesflat.push(pipes.childread)
        childpipesflat.push(pipes.childwrite)

        parentpipesflat.push(pipes.parentread)
        parentpipesflat.push(pipes.parentwrite)

        outputpipes[user] = pipes.parentread

        // queue up the input on each of the pipes
        for (var i in inputs[user]) {
            console.log("writing user input to fd = " + pipes.parentwrite)
            fs.writeSync(pipes.parentwrite, inputs[user][i])
        }

        // compile a list of pipes and users to provide to the contract as stdin
        fdlist += user + '=' + pipes.childread + ":" + pipes.childwrite + '\n'

    }

    console.log(fdlist)

    var bin = [ node.binary ]
    for (var i in node.binargs) bin.push(node.binargs[i])


    //dbg('Contract Execution: ' + bin)

    var stdout = pipe.rawforkexecclose(childpipesflat, parentpipesflat, bin, fdlist, node.dir)
    //var stdout = ""
    console.log(stdout)

    // collect outptuts
    // every connection has an entry in the inputs obj even if its []
    var outputs = {}
    for (var user in outputpipes) {

        //console.log(Buffer.from(pipe.getfdbytes(outputpipes[user])).toString())
        var out = Buffer.from(pipe.getfdbytes(outputpipes[user]))
        if (out.length >0)
            outputs[user] =  [sodium.to_hex(out)]
    }

    // close all the pipes we're finished with
    for (var i in parentpipesflat)
        fs.closeSync(parentpipesflat[i])

    console.log("stdout of contract: \n" + stdout)

    // these will be proposed in the next novel proposal (stage 0 proposal)
    ram.consensus.local_output_dict = outputs
}


function init_ram() {




    // IP:PORT -> ws for all peers
    ram.peer_connections = {}

    // IP:PORT -> ws for all public connections that haven't passed challenge
    ram.public_connections_unauthed = {}

    // IP:PORT;pubkeyhex -> ws for all public connections that have passed challenge
    ram.public_connections_authed = {}

    // IP:PORT;pubkeyhex -> [ ordered list of input packets ]
    // these are any messages we've received from authed public connections
    // that haven't yet been placed into a proposal
    ram.local_pending_inputs = {}

    // as above however they have been placed into a proposal and are waiting for validation
    ram.local_pending_inputs_old = {}


    // contains a dict comprising SHA512H -> time received
    ram.recent_peer_msghash = {}
    
    // ram.consensus contains all transient state information about consensus 
    ram.consensus = {}

    // this stores incoming proposals
    ram.consensus.proposals = {}
    
    // this is a dictionary mapping hashes of inputs to actual inputs
    // in the first stage of proposal full inputs are gossiped
    // in subsequent stages of proposal only the hash is gossiped
    ram.consensus.possible_input_dict = {}

    // as above
    ram.consensus.possible_output_dict = {}

    // this stores the result of local execution for proposal in stage 0 
    ram.consensus.local_output_dict = {}
  
    // set lcl to genesis, this will be override by load_contract usually
    ram.consensus.lcl = 'genesis' 

    // we'll keep a log of the last 100 ledger hashes
    // llcl->lcl
    ram.consensus.ledger_history = {}

    // this variable contains the lcl of the last ledger requested from a peer
    ram.consensus.last_history_request = false

}

// hotpocket controller entry point
function main() {

    // process cmdline if present
    process_cmdline(process.argv)
    
    // set up working structures
    init_ram()

    // load config
    load_contract()
  
    // start listening for peers
    open_listen()
 
    // connect to peers
    peer_connection_watchdog()

    // set up ram structure pruning/gc
    prune_cache_watchdog()

    // do consensus rounds!
    ram.consensus.stage = 0
    var consensus_round_timer = ()=>{ 
            consensus()
            setTimeout(consensus_round_timer, ram.consensus.nextsleep) 
    }
    consensus_round_timer()

}
