const HP_VERSION = 0.1
const fs = require('fs')
const ws_api = require('ws');
const sodium = require('libsodium-wrappers')
const crypto = require('crypto')
const pipe = require('posix-pipe-fork-exec')
const readline = require('readline')
const jsdiff = require('diff')
const fse = require('fs-extra')
const bsdiff = require('bsdiff-nodejs')

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
    if (ram.last_warn == message || ram.second_last_warn == message) return
    console.log("WARN: " + message)
    ram.second_last_warn = ram.last_warn
    ram.last_warn = message
}

// helper from https://stackoverflow.com/questions/56134298/is-there-a-way-to-get-all-keys-inside-of-an-object-including-sub-objects
const get_all_keys = obj => Object.keys(obj).flatMap(k => Object(obj[k]) === obj[k] ? [k, ...get_all_keys(obj[k])] : k).sort()

function key_of_highest_value(obj) {
    var highestval = Math.max(...Object.values(obj))

    for (var i in obj) 
        if (obj[i] == highestval) return i

    return null
}

// removes the contract directory from the front of strings
function prune_state_dir(x) { return x.replace(new RegExp('^' + node.dir + '/(\.prev_)?state/'), '') }

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


/**
    Return the modified file timestamp
**/
function get_modified_time(fn) {
    var stat = false
    try {
        stat = fs.statSync(fn)
    } catch (e) {}
    if (!stat) {
        warn('tried to get modified time of ' + fn + ' but file couldn\'t be accessed, this may cause desync')
        return 0
    }
    return stat.mtimeMs
}

/**
    Generates an SHA512 half of the specified file
**/
function generate_file_hash(fn) {
    var fd = -1
    try {
        fd = fs.openSync(fn)
    } catch (e) {
        warn('could not open ' + fn + ' for reading, this will likely cause a desync')
        return false
    }

    // read up to 64 mb at a time
    const max_read = 64*1024*1024
    var hasher = crypto.createHash('sha512')
    var buffer = Buffer.alloc(max_read)
    var bytes_read = 0

    while ( (bytes_read = fs.readSync(fd, buffer, 0, max_read, null)) > 0 ) {
        var partial_buffer = (bytes_read == max_read ? buffer : buffer.slice(0, bytes_read) )
        hasher.update( (bytes_read == max_read ? buffer : buffer.slice(0, bytes_read) ) )
    }

    try {
        fs.closeSync(fd)
    } catch(e) {}

    return hasher.digest('hex').slice(0,64)
}


/** 
    Generates a flat map of paths under the specified directory to the mapping_func
    e.g { 'blah/a' => mapping_func('blah/a') }
**/
function generate_directory_state(dir, nojson, mapping_func, fn_prune_func) {

    var output = {}
    var entries = fs.readdirSync(dir)

    for (var i in entries) {
        if (entries[i].match(/^\./)) continue
        var stat = {}
        try {
            stat = fs.statSync(dir + '/' + entries[i])
        } catch(e) {
            warn('could  not stat ' + dir + '/' + entries[i] + ' for state generation, this will likely cause a desync')
            continue
        }

        // if the entry is a directory we will recurse into it
        if (stat.isDirectory()) {
            output = Object.assign({}, output, generate_directory_state(dir + '/' + entries[i], true, mapping_func, fn_prune_func) )
            continue
        }

        // if the entry is a file we will generate sha512half of it
        if (stat.isFile()) {
            var fn = dir + '/' + entries[i]
            var value = mapping_func(fn)
            if (fn_prune_func)  {
                fn = fn_prune_func(fn)
                if (!fn) continue
            }
            output[fn] = value
            continue
        }

        warn('ignoring ' + dir + '/' + entries[i] + ' as it does not appear to be either a directory or a file')
    }

    // this is to ensure keys are sorted in the output
    return ( nojson ? JSON.parse(JSON.stringify(output, get_all_keys(output))) : JSON.stringify(output, get_all_keys(output)) )
}

/**
    Generates a diff between an old object and a new object
**/
function diff_objects(old_state, new_state) {

    try {
        old_state = (typeof(old_state) == 'string' ? JSON.parse(old_state) : old_state)
        new_state = (typeof(new_state) == 'string' ? JSON.parse(new_state) : new_state)
    } catch (e) {
        warn('attempted to diff states but one of the states was not valid json or an object')
    }
 
    var output = {
        created: {},
        updated: {},
        deleted: {}
    } 

    var new_files = Object.keys(new_state).sort()
    var old_files = Object.keys(old_state).sort()

    var array_diff_result = jsdiff.diffArrays(old_files, new_files)
    for (var i in array_diff_result) {
        var adr = array_diff_result[i]
        for (var j in adr.value) {
            var fn = adr.value[j]
            var hash = (adr.added ? new_state[fn] : old_state[fn])
            var action = (adr.added ? 'created' : ( adr.removed ?  'deleted' : 'updated' ) )
            // check if there was an actual update
            if (action == 'updated' && new_state[fn] == old_state[fn])
                    continue
            
            output[ action ][fn] = hash
        }
    }

    return output
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
    
    if ( !(config.binary.match(/^\//) && fs.existsSync(config.binary)) &&
         !fs.existsSync(node.dir + '/' + config.binary)
       ) die('contract binary not found at ' + node.dir + '/' + config.binary)
   
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
    for (var i in node.peers) {
        var ip = node.peers[i].ip 
        var port = node.peers[i].port
        if (ip == '0.0.0.0') ip = '127.0.0.1'
        peer_ips[ip + ":" + port] = true
    }
    // delete from that list every IP we do already have an active connection with
    for (var i in ram.peer_connections) {
        if (peer_ips[i]) delete peer_ips[i]
    }

    //dbg('peer connections ' + Object.keys(ram.peer_connections).length/2)

    // finally attempt new connections to anyone left on the list
    for (var i in peer_ips) {
        var ws = false
        var url = 'ws://' + i 
        try {
            ws = new ws_api(url)
            ws.on('error', e=>{
                //warn('attempted to connect to peer ' + i + ' but could not connect')
                //warn(e)
            })
            ws.on('open',((w)=>{return ()=>{on_peer_connection(w)}})(ws))        
        } catch (e) {
           // warn('attempted to connect to peer ' + i + ':' + peer_ips[i] + ' but could not connect')
        }
    }
    
    setTimeout(peer_connection_watchdog, node.roundtime*4)
}

function npl_watchdog() {
    if (ram.execution.pid > 0) { 
        process_npl_messages()
        setTimeout(npl_watchdog, 1)
    }
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

        if (ram.public_connections_authed[ws._authed]) {
            console.log('removing from authed')
            delete ram.public_connections_authed[ws._authed]
        }


        if (ram.public_connections_unauthed[ws._socket.remoteAddress + ":" + ws._socket.remotePort])
        {
            console.log('removing from unauthed')
            delete ram.public_connections_unauthed[ws._socket.remoteAddress + ":" + ws._socket.remotePort]
            
        }
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
    var time = Math.floor(Date.now()/1000)
    for (var i in ram.recent_peer_msghash)
        if (ram.recent_peer_msghash[i] < time - 60)
            delete ram.recent_peer_msghash[i]

    setTimeout(prune_cache_watchdog, 1000)
}

function prune_history_watchdog() {

    // grab the history director's mtimes
    var modification_times = generate_directory_state( node.dir + '/hist', 
                                true, get_modified_time )

    // flip the map
    modification_times = swap_keys_for_values(modification_times)

    var mtime_sorted = Object.keys(modification_times).sort().reverse()

    // todo: don't delete history newer than a certain time    

    var history_to_delete = mtime_sorted.length - 100 // todo: this is a magic number (size of history to keep)
    if (history_to_delete > 0) 
        for (var i = 0; i < history_to_delete; ++i)
            try {
                fs.unlinkSync(modification_times[mtime_sorted[i]])
            } catch (e) {
                warn('tried to delete old history ' + modification_times[mtime_sorted[i]] + ' but couldn\'t')
            }
    
    setTimeout(prune_history_watchdog, 15000)
}


function on_peer_connection(ws) {
    //todo: filter to by ip ensure peer is on peer list
    //dbg('peer connected *****************************************')
    ram.peer_connections[ws._socket.remoteAddress + ":" + ws._socket.remotePort] = ws
    ws.on('message', (message)=> {

        var time = Math.floor(Date.now()/1000)

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
        // todo: ensure each peer can send only one proposal for each stage on each lcl!!! important!!!
        if (msg.type == 'proposal' && contains_keys(msg, 'con', 'inp', 'out', 'lcl', 'stage', 'timestamp', 'type')) {
            ram.consensus.proposals[msg.pubkey + '-' + msg.stage] = msg
            // broadcast it to our peers
            broadcast_to_peers(message)

        } else if (msg.type == 'npl' && contains_keys(msg, 'data', 'lcl', 'timestamp')) {
            // node party line message
            ram.npl.push(msg)
            broadcast_to_peers(message)
        } else if (msg.type == 'sta_req' && contains_keys(msg, 'hash')) {

            // this message requests new state by providing the state the node currrently has
            // any files that differ will be sent wholesale
            // todo: figure out a way to efficiently bsdiff these files and send a patch instead

            var response = {
                type: 'sta_resp',
                req: SHA512H(JSON.stringify(msg.hash, get_all_keys(msg.hash)), 'STATE'),
                diff: {},
                copy: {}  // this is like patch except it will contain hex encoded binary data to override the target file
            }

            // first go ahead and diff with our current state
            response.diff = diff_objects(msg.hash, ram.state.hash)

            // for those files that are updated or created add their contents to the copy object
            for (var fn in response.diff.created)
                response.copy[fn] = sodium.to_hex(fs.readFileSync(node.dir + '/state/' + fn))

            for (var fn in response.diff.updated)
                response.copy[fn] = sodium.to_hex(fs.readFileSync(node.dir + '/state/' + fn))

            // now send the reply
            // todo: test if an extremely large version of this messages needs to be split
            return ws.send(sign_peer_message(response).signed) 

        } else if (msg.type == 'sta_resp' && contains_keys(msg, 'req', 'diff', 'copy')) {

            // first check if we actually asked for a state transfer
            if (!ram.state.last_req || Math.floor(Date.now()/1000) - ram.state.last_req > 60) 
                return warn('peer sent us a state response, but we didn\'t ask for one recently')
                //todo: we should continue collecting consensus data, in particular patch data while
                // we wait for this message to arrive

            if (msg.req != SHA512H(JSON.stringify(ram.state.hash, get_all_keys(ram.state.hash)), 'STATE'))
                return warn('peer send us a state response but it doesn\'t match our existing state')
                //todo: punish peer?

            // execution to here means this state response can be used to patch our state 

            // write all the files sent
            for (var fn in msg.copy)
                try { 
                    fs.writeFileSync(node.dir + '/state/' + fn, Buffer.from(msg.copy[fn], 'hex'))
                } catch (e) {
                    warn('we were supposed to write a file state/' + fn + ' to catch up state, '+
                         'but we were unable to, this will probably cause a desync')
                }
            // delete everything that needs deleting according to diff
            for (var fn in msg.diff.deleted)
                try {
                    fs.unlinkSync(node.dir + '/state/' + fn)
                } catch (e) {
                    warn('we were supposed to delete a file state/' + fn + ' to catch up state, ' +
                         'but it\'s already gone or couldn\'t be deleted')
                }
            // update state hashes
            ram.state.hash = generate_directory_state(node.dir + '/state', true, generate_file_hash, prune_state_dir)

            // signal the proposal can resume
            ram.state.last_req = false

            dbg('state transfer received and applied')

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

            //dbg('requested_lcl', requested_lcl)

            var history_files = fs.readdirSync(node.dir + '/hist')
            for (var file in history_files) {
                var json = ""
                var raw = ""
                try {
                    json = JSON.parse(raw = fs.readFileSync( node.dir + '/hist/' + history_files[file]).toString())
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

            response.hist[requested_lcl] = history_raw[requested_lcl]

            while (history_map[requested_lcl]) {
                // we found the history they were after, so attach it to the response and then 
                // check if there's another ledger after the one we found
                response.hist[requested_lcl] = history_raw[requested_lcl]

                // fetch the next in the sequence
                requested_lcl = history_map[requested_lcl]
            } 


            // send any fetched history to the peer
            return ws.send(sign_peer_message(response).signed)

        } else if (msg.type == 'hist_resp' && contains_keys(msg, 'hist')) {


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
                    received_history[lcl] = JSON.parse(received_history_raw[lcl] = msg.hist[lcl]) 
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

        } else {
            warn('received invalid message from peer ' + JSON.stringify(msg)) 
        }

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
    ram.consensus.nextsleep =  1//(sodium.randombytes_buf(1)[0]/256)*200// * node.roundtime 
}


/**
    Check our LCL is consistent with the proposals being made by our UNL peers
    lcl_votes -- dictionary mapping lcl -> number of peers who proposed for that lcl
    return value: true if proposing should stop for history catch up, 
                  false if proposing should continue
**/

function check_lcl_votes(lcl_votes) {

    var time = Math.floor(Date.now()/1000)
    
    var total_votes = 0 
    for (var i in lcl_votes)
            total_votes += lcl_votes[i]
    
    if (total_votes == 0) {
        warn('no votes')
        return true 
    }

    if (total_votes < node.unl.length * 0.8) {
        warn('not enough peers proposing to perform consensus')// (' + total_votes + ' out of ' + node.unl.length + 
          //   ', need ' + Math.ceil(node.unl.length*0.8) + ')')
        return true
    }

    var winning_lcl = key_of_highest_value(lcl_votes)

    var winning_votes = lcl_votes[winning_lcl]

    if ( winning_votes / node.unl.length < 0.8 ) // / total_votes < 0.8) 
    {
        // potential fork condition
        //warn('no consensus on lcl, fatal. votes were: ' + JSON.stringify(lcl_votes)) 
        //warn('waiting for lcl consensus')
        return true
    }

    // execution to here means the winning_lcl has 80%+ support

    if (ram.consensus.lcl != winning_lcl) {

        // create a history request
        request = {
            type: "hist_req",
            lcl: winning_lcl
        }
        
        ram.consensus.last_history_request = winning_lcl
        var signed_history_request = sign_peer_message(request).signed
        send_to_random_peer(signed_history_request) 
        warn('we are not on the consensus ledger, requesting history from a random peer')
        //dbg('winning_lcl', winning_lcl)
        //dbg('our lcl', ram.consensus.lcl)
        return true
    }

    return false
}
/** 
    Execute a consensus round 
**/
function consensus() {

    var time = Math.floor(Date.now()/1000)

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
        stage: ram.consensus.stage,
        time: 0//time // this differs from the timestamp, it is 'consensus time'
    }


    switch(ram.consensus.stage) {

        case 0: // in stage 0 we create a novel proposal and broadcast it
        {

            // we store all input until such time as the inputs make their way into a closed ledger            
            var pending_inputs = ram.local_pending_inputs

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
            proposal.sta = {}

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
                    }
                }
            }

            // propose outputs from previous round if any
            for (var user in ram.consensus.local_output_dict) 
                proposal.out[user] = ram.consensus.local_output_dict[user]
            
            // propose state 
            /*
                ram.state = {
                    patch: {},      // fn -> bsdiff patch going from previous state to new state
                    modified: {},   // fn -> last modified time for each file
                                    // fn -> hash, after current execution 
                    hash: {}
                                    // fn -> hash, previous execution 
                    prev_hash: {}
                }
            */


            /* 
                State proposal anatomy:
                proposal.sta = {
                    prev: "aaaabbbb', // as below
                    curr: "deadbeef", // this is the hash of the total JSONified up to date ram.state.hash
                    diff: {
                        created: { fn => hash },
                        updated: { fn => hash },
                        deleted: { fn => hash }
                    },
                    patch: {
                        fn: <hex bspatch data>
                    }
                }
            */

            proposal.sta = {
                prev: SHA512H(JSON.stringify(ram.state.prev_hash, get_all_keys(ram.state.prev_hash)), 'STATE'),
                curr: SHA512H(JSON.stringify(ram.state.hash, get_all_keys(ram.state.hash)), 'STATE'),
                diff: diff_objects(ram.state.prev_hash, ram.state.hash),
                patch: ram.state.patch
            }

            ram.consensus.novel_proposal_time = time
            //proposal.sta = {}
            
            if (!ram.consensus.nprop) ram.consensus.nprop = {}
            var ts = proposal.timestamp
            delete proposal.timestamp
            var h = SHA512H(JSON.stringify(proposal, get_all_keys(proposal)), 'NPROP')
            proposal.timestamp = ts
            if (!ram.consensus.nprop[h]) {
                ram.consensus.nprop[h] = true                
                //dbg('novel prop', proposal)
            } //else console.log('sent same proposal again')
            

            proposal.time = time

            broadcast_to_peers(sign_peer_message(proposal).signed)

            break
        }

        case 1:
        case 2:
        case 3:
   

 
            var proposals = ram.consensus.proposals
            //ram.consensus.proposals = {}

            

            // we need to consider what our peers believe the LCL is first before we can participate in voting
            // if our peers have different ideas of what the LCL is we might be in a fork condition
            // and need to halt, alternatively if > 80% agree on an LCL different to ours we need to request
            // history first and are not currently ready to vote

            lcl_votes = {}

            stage_votes = {}

            for (var i in proposals) {
                if (proposals[i].lcl == ram.consensus.lcl)
                    inc(stage_votes, proposals[i].stage)

                if (time - proposals[i].timestamp < node.roundtime * 4 && 
                    proposals[i].stage == ram.consensus.stage - 1) {
                    inc(lcl_votes, proposals[i].lcl)
                }
            }
            var winning_stage = -1
            var largestvote = 0
            for (var i in stage_votes) {
                if (stage_votes[i] > largestvote) {
                    largestvote = stage_votes[i]
                    winning_stage = i
                }
            }

            // check if we're ahead of consensus
            if (winning_stage < ram.consensus.stage - 1) {
                //console.log('wait for proposals 3a --- ' + winning_stage)
                //dbg('stage votes', stage_votes)
                return wait_for_proposals(time - ram.consensus.novel_proposal_time < Math.floor(node.roundtime/1000))
            } else if (winning_stage > ram.consensus.stage - 1) {
                // we're behind consensus
                warn('wait for proposals 3b')
                return wait_for_proposals(true)
            }


            if (check_lcl_votes(lcl_votes)) {
                //dbg('consensus failure no lcl agreement, or simply no proposals')
                return wait_for_proposals(time - ram.consensus.novel_proposal_time < Math.floor(node.roundtime/1000))
            }

            // execution to here means we are on the consensus ledger
            
            // set up our voting counters
            var votes = {
                con: {},
                inp: {},
                out: {},
                sta: {},
                time: {}
            }

            for (var i in proposals) {
                var p = proposals[i]

                // everyone votes on an arbitrary time, as long as its within the round time
                // and not in the future
                if (time > p.time && time - p.time < node.roundtime)  
                    inc(votes.time, p.time)

                for (var j in p.con)
                    inc(votes.con, p.con[j])
   
                for (var j in p.inp) {
                    // inputs are processed as a hash of the JSON of the proposed input
                    var hash = ""
                    if (typeof(p.inp[j]) == "object") {
                        // this is a full input proposal, so we need to hash it
                        var possible_input = {}
                        possible_input[j] = p.inp[j]
                        hash = SHA512H(JSON.stringify(possible_input), 'INP')
                        ram.consensus.possible_input_dict[hash] = possible_input

                    } else {
                        // this is already a hash
                        hash = p.inp[j]
                    }

                    inc(votes.inp, hash)
                }

                // repeat above for outputs
                for (var j in p.out) {
                    // output are processed as a hash of the JSON of the proposed input
                    var hash = ""
                    if (typeof(p.out[j]) == "object") {
                        // this is a full output proposal, so we need to hash it

                        var possible_output = {}
                        possible_output[j] = p.out[j]
                        hash = SHA512H(JSON.stringify(possible_output, get_all_keys(possible_output)), 'OUT')
                        ram.consensus.possible_output_dict[hash] = possible_output
                    } else {
                        // this is already a hash
                        hash = p.out[j]
                    }

                    inc(votes.out, hash)
                }

                // repeat above for state
                {
                    var hash = ""
                    if (typeof(p.sta) == "object") {
                        if (p.stage > 0) {
                            warn("peer proposal attempted to propose a full state in a stage > 0")
                            //dbg('state', p)
                        } else {
                            hash = SHA512H(JSON.stringify(p.sta, get_all_keys(p.sta)), 'STA')
                            ram.consensus.possible_state_dict[hash] = p.sta
                        }
                    } else {
                        // this is already a hash
                        hash = p.sta
                    }

                    inc(votes.sta, hash)
                }

            }


            // threshold the votes and build a new proposal
            var vote_threshold = ( ram.consensus.stage == 1 ? 0.50 * node.unl.length : 
                                 ( ram.consensus.stage == 2 ? 0.65 * node.unl.length :
                                 ( ram.consensus.stage == 3 ? 0.80 * node.unl.length : -1 )))


            // todo: check if inputs being proposed by another node are actually spoofed inputs
            // from a user locally connected to this node, if they are publish a repuduation?

            // if we're at proposal stage 1 we'll accept any input and connection that has 1 or more vote            

            for (var i in votes.con)
                if (votes.con[i] >= vote_threshold || votes.con[i] > 0 && ram.consensus.stage == 1)
                    proposal.con.push(i)

            for (var i in votes.inp)
                if (votes.inp[i] >= vote_threshold || votes.inp[i] > 0 && ram.consensus.stage == 1)
                    proposal.inp.push(i)

            for (var i in votes.out)
                if (votes.out[i] >= vote_threshold)
                    proposal.out.push(i)

            // sort sta votes
            votes.sta = JSON.parse(JSON.stringify(votes.sta, get_all_keys(votes.sta)))

            // if we have two nodes and they disagree about the state the mathematically
            // largest hash will now win
            var largest_vote = 0
            for (var i in votes.sta) {
                if (votes.sta[i] >= vote_threshold && votes.sta[i] > largest_vote) {
                    largest_vote = votes.sta[i]
                    proposal.sta = i
                }
            }

            // time is voted on a simple sorted and majority basis, 
            // there will always be disagreement
            votes.time = JSON.parse(JSON.stringify(votes.time, get_all_keys(votes.time)))
            largest_vote = 0
            for (var i in votes.time) {
                if (votes.time[i] > largest_vote) {
                    largest_vote = votes.time[i]
                    proposal.time = i
                }
            } 

            // we always vote for our current lcl regardless of what other peers are saying
            // if there's a fork condition we will either request history and state from 
            // our peers or we will halt depending on level of consensus on the sides of the fork
            
            proposal.lcl = ram.consensus.lcl


            for (var i in proposals)
                if (proposals[i].stage < ram.consensus.stage)
                    delete proposals[i] 

            var peer_msg = sign_peer_message(proposal)
            var proposal_msg_unsigned = peer_msg.unsigned

            // finally send the proposal to peers
            broadcast_to_peers(peer_msg.signed) 


            if (ram.consensus.stage == 3) {
                //dbg('lcl', proposal)
                apply_ledger(proposal)
            }            
    }

    // after a novel proposal we will just busy wait for proposals
    if (ram.consensus.stage > 0)
        ram.consensus.nextsleep = Math.floor(node.roundtime/4)
    else ram.consensus.nextsleep = 1

    ram.consensus.stage = (ram.consensus.stage + 1) % 4  
}

// called with a stage 3 proposal at the end of a consensus round
function apply_ledger(proposal) {

    // we've reached the end of a consensus round

    // so we need to apply inputs, collect outputs
    // and clear buffers, and assign unused inputs to next round

    // here ledger is the encoded string version of the closed ledger,
    // proposal is the object form
    

    // prune off timestamp, pubkey, signature
    delete proposal.pubkey
    delete proposal.timestamp
    delete proposal.sig
    delete proposal.stage

    var ledger = JSON.stringify(proposal, get_all_keys(proposal))

    // lcl = last closed ledger
    var lcl = SHA512H( ledger, 'LEDGER' )

    dbg('last closed ledger: ' + lcl)

    // write the new lcl to history
    var fd = fs.openSync( node.dir + '/hist/' + lcl, 'w' )
    fs.writeSync(fd, ledger)
    fs.closeSync(fd)

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
                warn('output represented by hash ' + hash + ' was not valid hex') 
                continue
            } 

            // check if the user is in our locally connected users
            for (var j in ram.public_connections_authed) {
                if (j.replace(/^.*;/, '') == user) {
                    // this is our locally connected user, send his contract output to him
                    ram.public_connections_authed[j].send(output)
                    break
                }
            }
        }
    }

    // now we can safely clear our output dictionary
    ram.consensus.possible_output_dict = {}

    // check our state against the winning / canonical state
    var curr = SHA512H(JSON.stringify(ram.state.hash, get_all_keys(ram.state.hash)), 'STATE')
    var canonical = ram.consensus.possible_state_dict[proposal.sta]
    if (!canonical) {
        warn('could not find consensus state in our possible state dict, this will cause desync')
    } else if (canonical.curr != curr) {

        // first check to ensure our previous state is the same as the canonical previous state
        var prev = SHA512H(JSON.stringify(ram.state.prev_hash, get_all_keys(ram.state.prev_hash)), 'STATE')
        if (canonical.prev == prev) {
           
            // file system isn't in sync, but our previous state is, so do a roll back to that 
            warn('our file state differed from consensus, rolling back and patching now')
            
            dbg('canonical state', canonical)
            dbg('our state', ram.consensus.state)

            rollback_state() 

            apply_state_patch(node.dir + '/state' , canonical.patch)

            // now we should have the canonical state, but let's double check if that's true
            // if we don't we'll need to request the state

            var hash = generate_directory_state(node.dir + '/state', true, generate_file_hash, prune_state_dir)
            
            curr = SHA512H(JSON.stringify(hash, get_all_keys(hash)), 'STATE')

            if (canonical.curr != curr) {
                warn('even after rolling back and applying state patches the file system is not on consensus, ' +
                    'requesting state from peer')

                request_state_from_peer()

                warn('wait for proposals 1')
                return wait_for_proposals(true)
            }
        } else {

            // the canonical previous state is not the same as our previous state, we'll need to do a
            // state request from our peers before we can continue

            request_state_from_peer()
            warn('wait for proposals 2')
            return wait_for_proposals(true)
        }
    }

    // and our state change dict
    ram.consensus.possible_state_dict = {}

    // structure we need to provide to the contract binary run routine:
    // { user_pub_key: [ stream of raw input or empty if no input is available ] }
    // every connected user must have an entry

    //dbg("closed ledger", proposal)

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

        for (var user in ram.consensus.possible_input_dict[hash]) {
            // there'll be just the one key
            var inputshex = ram.consensus.possible_input_dict[hash][user]
            
            var inputsbuf = []
            for (var k in inputshex) {
                inputsbuf[k] = Buffer.from(inputshex[k], 'hex')
               
                // todo: this hacky code assumes very small user inputs, 
                // this should be revised for efficiency (following two for loops)
                // remove entries from pending inputs that made their way into
                // a closed ledger
                var fulluser = ""
                for (var fu in ram.local_pending_inputs)
                    if (fu.replace(/^.*;/,'') == user) {
                        fulluser = fu
                        break
                    }
                for (var l in ram.local_pending_inputs[fulluser]) {
                    if (sodium.to_hex(ram.local_pending_inputs[fulluser][l]) == 
                        inputshex[k])
                        delete ram.local_pending_inputs[fulluser][l]
                }
            }

            // check if the pending input for this user contains any more data
            if (ram.local_pending_inputs[user] &&
                Object.keys(ram.local_pending_inputs[user]).length == 0)
                delete ram.local_pending_inputs[user]
            
            concrete_inputs[user] = inputsbuf
            break
        }
    }

    // clear possible input dictionary since we've materalised the actual inputs
    ram.consensus.possible_input_dict = {}

    ram.execution.pid = 0 // this will force a new execution, once this is > 0 func is re-entrant
    ram.execution.inputs = concrete_inputs
    ram.execution.ledger = proposal

    run_contract_binary()

}

// watches the npl pipe connected to an executing contract
// and transmits/retrieves the messages into/from the appropriate websocket connection/s
function process_npl_messages() {

    // process incoming messages first
    var incoming = ram.npl
    ram.npl = []

    for (var i in incoming) {
        var msg = incoming[i]
        if (msg.lcl != ram.execution.ledger.lcl) {
            warn('we had an npl message but it was for the wrong lcl, discarding')
            warn(msg.lcl + ' =/= ' + ram.execution.ledger.lcl)
            continue
        }

        var buf = Buffer.from(msg.data, 'hex')
        var header = Buffer.from('Length: ' + buf.length + '\nPubkey: ' + msg.pubkey + '\n\n')
        // write into pipe
        fs.writeSync(ram.execution.pipe.npl[1], Buffer.concat([header, buf])) 
        dbg('npl data', buf.toString())
    }

    // handle outgoing messages
    var buf = Buffer.from(pipe.getfdbytes(ram.execution.pipe.npl[0]))
    if (buf.length > 0) {
        // create and sign a message
        var npl_datagram = {
            type: 'npl',
            data: sodium.to_hex(buf),
            timestamp: Math.floor(Date.now()/1000),
            lcl: ram.execution.ledger.lcl
        }
        var signed = sign_peer_message(npl_datagram).signed
        
        // send to every peer
        for (var peer in ram.peer_connections) 
            ram.peer_connections[peer].send(signed)
    }

}


/**
    runs the contract binary against a proposal
    this function is re-entrant, and called until execution has finished
**/
function run_contract_binary() {

    var inputs = ram.execution.inputs
    var proposal = ram.execution.ledger
    var pid = ram.execution.pid

    // if the contract is already running we need to check its progress
    if (pid) {
        var output  = pipe.rawforkexecclose([], [], [], "", node.dir, ram.execution.pid)

        // if still executing, process any npl messages then return
        if (typeof(output) == 'number') { 
            return
        }

        //dbg('contract output: ' + Buffer.from(output).toString())

        // execution to here means the contract has finished execution
        handle_state_after_execution()

        // collect outptuts
        // every connection has an entry in the inputs obj even if its []
        var outputs = {}
        for (var user in ram.execution.pipe.user) {

            //console.log(Buffer.from(pipe.getfdbytes(outputpipes[user])).toString())
            var out = Buffer.from(pipe.getfdbytes(ram.execution.pipe.user[user]))
            if (out.length > 0) {
                outputs[user] =  [sodium.to_hex(out)]
                dbg("contract produced " + out.length + " bytes of output on fd " +
                     ram.execution.pipe.user[user])
            }

        }

        // close all the pipes we're finished with
        for (var i in ram.execution.pipe.close) 
            try {
                fs.closeSync(ram.execution.pipe.close[i])
            } catch (e) {}

        // these will be proposed in the next novel proposal (stage 0 proposal)
        ram.consensus.local_output_dict = outputs

        // we've finished execution
        ram.execution.pid = 0

        return
    }

    ram.execution.pipe.user = {}
    ram.execution.pipe.npl = []
    ram.execution.pipe.close = []

    var childpipesflat  = []     // pipes.childread, pipes.childwrite ]
    var parentpipesflat = []    // pipes.parentread, pipes.parentwrite ]

    /**
        anatomy of a hp fdlist
        {
            hotpocket: <version>,
            type: 'binexec', 
            mver: 1,    
            time: <utc timestamp>,      // nodes can't use their own time or it will be non deterministic
            pubkey: <public key hex>,  // this node's public key
            unl: [<pubkey hex>],
            user: {
                <public key hex>: [<fd for reading from this user>, <fd for writing to this user>], ...
            },
            // these fd's allow the node realtime communication with it's peers through the 
            // non-consensus-channel NCC message type
            ncc: {
                <public key hex>: [<fd for reading from this node>, <fd for writing to this node>], ...
            }
        }

    **/


    var fdlist = {
        hotpocket: HP_VERSION,
        type: 'binexec',
        mver: 1, // this is the message version type    
        time: proposal.time,
        pubkey: node.pubkeyhex,
        unl: [],
        npl: [], // node to node party line
        user: {},
        lcl: proposal.lcl
    }

    // add the UNL
    for (var i in node.unl)
        fdlist.unl.push(node.unl[i].hex)
    
    // create node to node party line
    // messages coming in on this line are of the following format
    // Length: <number of bytes>\n
    // Sender: <pubkeyhex of sender>\n\n
    // <binary data>
    // messages going out need no header, just write to the pipe
    {
        // create pipes for node to node communication
        var pipes = pipe.PipeDuplex()

        childpipesflat.push(pipes.childread)
        childpipesflat.push(pipes.childwrite)
        parentpipesflat.push(pipes.parentread)
        parentpipesflat.push(pipes.parentwrite)
        
        fdlist.npl = [ pipes.childread, pipes.childwrite ]

        ram.execution.pipe.npl = [ pipes.parentread, pipes.parentwrite ]
    }

    for (var user in inputs) {
        var pipes = pipe.PipeDuplex()
        
        childpipesflat.push(pipes.childread)
        childpipesflat.push(pipes.childwrite)

        parentpipesflat.push(pipes.parentread)
        parentpipesflat.push(pipes.parentwrite)

        ram.execution.pipe.user[user] = pipes.parentread

        // queue up the input on each of the pipes
        for (var i in inputs[user]) 
            fs.writeSync(pipes.parentwrite, inputs[user][i])

        // this is all that will ever be written to this pipe so we can close it
        fs.closeSync(pipes.parentwrite)

        // compile a list of pipes and users to provide to the contract as stdin
        fdlist.user[user] = [ pipes.childread, pipes.childwrite ]
    }
    
    ram.execution.pipe.close = parentpipesflat
    
    //sort keys and remove whitespace
    fdlist = JSON.stringify(fdlist, get_all_keys(fdlist), 1)


    var bin = [ node.binary ]
    for (var i in node.binargs) bin.push(node.binargs[i])

    prepare_state_before_execution()

    ram.execution.pid = pipe.rawforkexecclose(childpipesflat, parentpipesflat, bin, fdlist, node.dir, 0)
    
    npl_watchdog()
}

function request_state_from_peer() {

    var request = {
        type: "sta_req",
        hash: ram.state.hash
    }

    // update the last state request flag              
    ram.state.last_req = Math.floor(Date.now()/1000)

    //todo: we should continue collecting consensus data, in particular patch data while
    // we wait for this message to arrive
    send_to_random_peer(sign_peer_message(request).signed)   

}

function apply_state_patch(dir, patch) {
    for (var fn in patch) {
        // write the patch file
        // todo: fork bsdiff so we don't have to write a temp file first

        var path = dir + '/' + fn       
 
        // first check if the target file exists
        var stat = false
        try {
            stat = fs.statSync(path)
        } catch (e) {}

        // file doesn't exist so we'll create a blank file to apply patch to
        if (!stat)
           fs.writeFileSync(path, Buffer.alloc(0)) 

        var patchfn = dir + '/.tmp_patch'
        try {
            fs.writeFileSync(patchfn, Buffer.from(patch[fn], 'hex'))
        } catch (e) {
            warn('tried to apply a patch to /' + path + ' but could not, this will probably cause a desync (1)')
            console.log(e)
        }

        try {
            bsdiff.patchSync(path, path, patchfn)
            fs.unlinkSync(patchfn)
        } catch (e) {
            warn('tried to apply a patch to /' + path + ' but could not, this will probably cause a desync (2)')
            console.log(e)
        }
    }
}

function rollback_state() {
    var new_modified_times = generate_directory_state(node.dir + '/state', true, get_modified_time, prune_state_dir)
    for (var fn in new_modified_times) {
        if (ram.state.modified[fn] && !new_modified_times[fn] ||
            ram.state.modified[fn] < new_modified_times[fn]) {
            // file was erronously deleted or modified, so copy it back
            fse.copySync(node.dir + '/.prev_state/' + fn, node.dir + '/state/' + fn)
        } else if (!ram.state.modified[fn] && new_modified_times[fn]) {
            // file was erronously created so delete it
            fs.unlinkSync(node.dir + '/state/' + fn)
        }
    }    
}

function prepare_state_before_execution() {
/*
    ram.state = {
        patch: {},      // fn -> bsdiff patch going from previous state to new state
        modified: {},   // fn -> last modified time for each file
                        // fn -> hash, after current execution 
        hash: {}
                        // fn -> hash, previous execution 
        prev_hash: {}
    }
*/

    // check if shadow state directory exists, if it doesn't make it
    // this will only execute on new contracts, generally speaking
    var prev_stat = false
    try {
        prev_stat = fs.statSync(node.dir + '/.prev_state')
    } catch (e) {}
    if (!prev_stat) {
        // directory doesn't exist, we'll need to do a cp -r
        warn('copy of state not found, making copy now (this is typical for first run)')
        fse.copySync(node.dir + '/state', node.dir + '/.prev_state')
    }

    if (!ram.state.prev_hash) {
        // set up data structures as needed for a first run
        ram.state.prev_hash = generate_directory_state(node.dir + '/.prev_state', true, generate_file_hash, prune_state_dir)
        ram.state.hash = ram.state.prev_hash
        ram.state.patch = {}
        ram.state.modified = generate_directory_state(node.dir + '/state', true, get_modified_time, prune_state_dir)
        return
    }

    // execution to here means there's already a previous state directory
    // so this is a regular state cycle

    // first let's see if there have been any file additions of deletions since last run
    var new_modified_times = generate_directory_state(node.dir + '/state', true, get_modified_time, prune_state_dir)  
    // we can do this by running a key diff between new modified times and previous modified times
    
    var diff = diff_objects(ram.state.modified, new_modified_times)
    
    // apply creations and deletions
    for (var fn in diff.created)
        try { 
            fse.copySync(node.dir + '/state/' + fn, node.dir + '/.prev_state/' + fn)
        } catch (e) {
            warn('tried to copy /state/' + fn + ' but could not, this will probably cause a desync') 
        }
    for (var fn in diff.deleted)   
        try {
            fs.unlinkSync(node.dir + '/.prev_state/' + fn)
        } catch (e) {
            warn('tried to delete /.prev_state/' + fn + ' but could not, this will probably cause a desync')
        }


    // apply any pending patches
    for (var fn in ram.state.patch) {
        // write the patch file
        // todo: fork bsdiff so we don't have to write a temp file first
        try {
            var patchfn = node.dir + '/.prev_state/.tmp_patch'
            fs.writeFileSync(patchfn, Buffer.from(ram.state.patch[fn], 'hex'))
            bsdiff.patchSync(node.dir + '/.prev_state/' + fn, node.dir + '/.prev_state/' + fn, patchfn)
            fs.unlinkSync(patchfn)
        } catch (e) {
            warn('tried to apply a patch to /.prev_state/' + fn + ' but could not, this will probably cause a desync (3)') 
            console.log(e)
        }
    }   

    // clear patches
    ram.state.patch = {}  
 
    // now the prev state and current state are the same, so copy the sta over
    ram.state.prev_hash = ram.state.hash

    // ensure last modified times are up to date
    ram.state.modified = new_modified_times

}


function handle_state_after_execution() {

    // contract has executed, first thing we need to look at is the modified times on its state files

    var new_modified_times = generate_directory_state(node.dir + '/state', true, get_modified_time, prune_state_dir)

    ram.state.hash = {}

    for (var fn in new_modified_times) {
        if (!ram.state.modified[fn] || new_modified_times[fn] > ram.state.modified[fn] ) {
            // this file was modified, we need to take a bsdiff
            var patchfn = node.dir + '/.prev_state/.tmp_patch'
            var stat = false
            try {
                stat =fs.statSync(node.dir + '/.prev_state/' + fn)
            } catch (e) {}
            if (!stat) {
                // this is a new file, it didn't exist last run
                // to facilitate its creationg in other nodes we'll produce a dummy file
                // and then generate a patch against it
                fs.writeFileSync(node.dir + '/.prev_state/' + fn, Buffer.from([]))
            }

            // todo: modify bsdiff to take state in memory
            bsdiff.diffSync(node.dir + '/.prev_state/' + fn, node.dir + '/state/' + fn, patchfn)

            // read the patch
            ram.state.patch[fn] = sodium.to_hex(fs.readFileSync(patchfn))
            fs.unlinkSync(patchfn)

            // generate new hash
            ram.state.hash[fn] = generate_file_hash(node.dir + '/state/' + fn)
          
        } else if (ram.state.prev_hash[fn]) {
            // copy the old sta for this file since it wasn't modified
            ram.state.hash[fn] = ram.state.prev_hash[fn]
        } else {
            ram.state.hash[fn] = generate_file_hash(node.dir + '/state/' + fn)
        }
    }   

}


function init_ram() {

    // this structure holds execution data for contract,
    // when pid is set > 0 the contract is still executing
    // and no consensus round should be performed
    ram.execution = {
        pid: 0,
        ledger: false,
        inputs: false,
        pipe: {
            user: {},   // pubkeyhex => fdin
            npl: [],   // [fdin, fdout] ** partyline for nodes to talk to eachother during execution 
            close: [] // fds that need to be closed after execution completes
        }
    }

    // this will hold pending npl messages from peers 
    ram.npl = []

    // IP:PORT -> ws for all peers
    ram.peer_connections = {}

    // IP:PORT -> ws for all public connections that haven't passed challenge
    ram.public_connections_unauthed = {}

    // IP:PORT;pubkeyhex -> ws for all public connections that have passed challenge
    ram.public_connections_authed = {}

    // IP:PORT;pubkeyhex -> [ ordered list of input packets ]
    // these are any messages we've received from authed public connections
    // that haven't yet been placed into a closed ledger
    ram.local_pending_inputs = {}

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
    
    // as above
    ram.consensus.possible_state_dict = {}

    // this stores the result of local execution for proposal in stage 0 
    ram.consensus.local_output_dict = {}

    // stores information about the progression of the file state under /state/ 
    // these structures are flat, fn is the full path to the file under /state/
    ram.state = {
        patch: {},      // fn -> bsdiff binary patch going from previous state to new state
        modified: {},   // fn -> last modified time for each file
                        // fn -> hash, after current execution 
        hash: {},
                        // fn -> hash, previous execution 
        prev_hash: false,
        last_req: 0
    }

    
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

    // history can get large quickly!
    prune_history_watchdog()

    // do consensus rounds!
    ram.consensus.stage = 0
    var consensus_round_timer = ()=>{
            
            if (ram.execution.pid) {
                // when the contract is in execution we will busy wait for it
                //dbg('waiting on pid = ' + ram.execution.pid)
                run_contract_binary()
                setTimeout(consensus_round_timer, 10) 
            } else { 
                consensus()
                setTimeout(consensus_round_timer, ram.consensus.nextsleep) 
            }
    }
    consensus_round_timer()

}
