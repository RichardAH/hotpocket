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

    // check roundtime
    if (!config.roundtime) die('must specify contract roundtime, try: "roundtime": "1000"')
    node.roundtime = parseInt('' + config.roundtime, 10)
    if (node.roundtime <= 0) die('round time must be >= 1 ms')

    // some public rate and size limits might be specified
    if (config.pubmaxcpm) node.pubmaxcpm = config.pubmaxcpm
    if (config.pubmaxsize) node.pubmaxsize = config.pubmaxsize

    // todo: check state
    // todo: check history

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

    if (node.pubport) {
        ram.public_server = new ws_api.Server({ port: node.pubport });
        ram.public_server.on('connection', on_public_connection)
        ram.public_server.on('close', on_public_close)
    }

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
        var ws = new ws_api('ws://' + i + ':' + peer_ips[i])
        ws.on('open',((w)=>{return ()=>{on_peer_connection(w)}})(ws))        
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

function on_peer_connection(ws) {
    //todo: filter to by ip ensure peer is on peer list
    ram.peer_connections[ws._socket.remoteAddress + ":" + ws._socket.remotePort] = ws
    ws.on('message', on_peer_message)
}


function on_public_connection(ws) {

    if (!node.pubport) die('received a public connection even though public port was not specified')
    //todo: filter by abuse/ip here to stop ddos
    ram.public_connections_unauthed[ws._socket.remoteAddress + ":" + ws._socket.remotePort] = ws
    var challenge = sodium.to_hex(sodium.randombytes_buf(16))
    ws.send(JSON.stringify({
        hotpocket: HP_VERSION,
        type: "public_challenge",
        challenge: challenge
    })
    ws._challenge = challenge 
    ws.on('message', function (message) => {
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

        if (!sodium.crypto_sign_verify_detached(msg.sig, msg.challenge, 
                Buffer.from(msg.pubkey, 'hex'))
            )
            return warn('received bad signature from unauthed pub node')
        
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

        // change where this socket's messages are routed to now
        ws.on('message', (message) => {
            ws._msgcount++
            if (message.length > node.pubmaxsize) return warn('received oversized authed public message')
            if ((Date.now() - ws._start) / ws._msgcount) return warn('received too many messages from authed public user')
            if (!ram.local_pending_inputs[ws._authed]) return warn('received authed message from a websocket without an _authed prop')
            ram.local_pending_inputs[ws._authed].push(message)
        })
    })
}


function prune_cache_watchdog() {

    var time = Date.now()
    for (var i in ram.recent_peer_msghash)
        if (ram.recent_peer_msghash[i] < time - 60)
            delete ram.recent_peer_msghash[i]

    setTimeout(prune_cache_watchdog, 60)

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

    // check the signature 
    // this is pretty expensive
    if (!sodium.crypto_sign_verify_detached(sig, msgnosig, Buffer.from(msg.pubkey, 'hex')))
        return warn('received bad signature from peer') // todo: punish peer

    // execution to here is a valid peer message

    // check what sort of message it is
    if (msg.type == 'proposal' && msg.con && msg.inp && msg.out && msg.lcl && msg.stage) {
        ram.proposals[msghash] = msg
        // broadcast it to our peers
        broadcast_to_peers(message)
    } else warn('received invalid message from peer') 

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


function dbg(m) {
    console.log('DBG: ' + m)
}

// helper function for voting
function inc(x, y) { if (x[y] == undefined) return x[y] = 1; return x[y]++; }

/** 
    Execute a consensus round 
**/
function consensus() {

    // wait for entry point into consensus cycles
    var time = (+ new Date())
    var start = time % node.roundtime*4
    if (ram.consensus.stage == 0 && start > 50) {
        ram.consensus.nextsleep = 1
        dbg('sleeping... waiting to join consensus ' + start + ' | ' + time + ' | ' + ram.consensus.nextsleep) 
        return
    }


    ram.consensus.nextsleep = node.roundtime - 200
    dbg('ready ' + time + " nextsleep = " + ram.consensus.nextsleep)

    if (ram.consensus.possible_input_dict == undefined) ram.consensus.possible_input_dict = {}
    if (ram.consensus.possible_output_dict == undefined) ram.consensus.possible_output_dict = {}
    

    proposal = {
        hotpocket: HP_VERSION,
        type: 'proposal',
        pubkey: node.pubkeyhex,
        timestamp: time
        con: [],
        inp: [],
        out: [],
        sta: "",
        lcl: "",
        stage: ram.consensus.stage
    }

    switch(ram.consensus.stage) {

        case 0: // in stage 0 we create a novel proposal and broadcast it
        {
           
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
                timestamp: time
                con: [],
                inp: {},
                out: [],
                sta: "",
                lcl: "",
                stage: 0
            }

            var pending_inputs = ram.local_pending_inputs
            ram.local_pending_inputs = {}

            for (var i in ram.public_connections_authed) {
                // add all the connections we host (mentioned by their public key only)
                proposal.con.push(i.replace(/^.+;/,''))

                // and all their pending messages
                if (pending_inputs[i] && pending_inputs[i].length > 0) {
                    proposal.inp[i] = []
                    for (var j in pending_inputs[i]) {
                        var user_input = pending_inputs[i][j]
                        proposal.inp[i].push(user_input)
            
                        //todo: old inputs need to be stripped from this object when consensus round closes
                        //any that didn't make it into the Nth round need to make it into N+1
                        ram.local_pending_inputs_old[i].push(user_input)
                    }
                }
            }

            // todo: gather and propose outputs
            // todo: gather and propose state
            // todo: gather and propose lcl


            break;
        }

        case 1:
        case 2:
        case 3:
    
            var proposals = ram.proposals
            ram.proposals = {}

            //todo: tally all the connections, inputs, outputs, state, lcl, from all proposals
            // and then propose a new proposal based on those tallies

            var votes = {
                con: {},
                inp: {},
                out: {},
                sta: {},
                lcl: {}
            }

            for (var i in proposals) {
                var p = proposals[i]

                inc(votes.sta, p.sta)
    
                inc(votes.lcl, p.lcl)

                for (var j in p.con)
                    inc(votes.con, p.con[j])
                
                for (var j in p.inp) {
                    // inputs are processed as a hash of the JSON of the proposed input
                    var hash = ""
                    if (typeof(p.inp[j]) == "object") {
                        // this is a full input proposal, so we need to hash it
                        var possible_input = {j: p.inp[j]}
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
                        var possible_output = {j: p.out[j]}
                        hash = SHA512H(JSON.stringify(possible_output), 'INPUT')
                        ram.consensus.possible_output_dict[hash] = possible_output
                    } else {
                        // this is already a hash
                        hash = p.out[j]
                    }

                    inc(votes.out, hash)
                }
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

            
    }

    // to sign we need to first JSON stringify it in a key sorted fashion
    var proposal_msg_unsigned = JSON.stringify(proposal, Object.keys(msg).sort())
    // create the signature
    var sig = sodium.crypto_sign_detached(proposal_msg_unsigned, node.seckeybuf)
    // then add the signature to the message and stringify it again
    proposal.sig = sig
    var proposal_msg = JSON.stringify(proposal, Object.keys(msg).sort())

    // finally send the proposal to peers
    broadcast_to_peers(proposal_msg) 


    ram.consensus.stage = (ram.consensus.stage + 1) % 4  
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
    peer_connection_watchdog()

    // set up ram structure pruning/gc
    prune_cache_watchdog()

    // do consensus rounds!
    ram.consensus = {}
    ram.consensus.stage = 0
    var consensus_round_timer = ()=>{ 
            consensus()
            setTimeout(consensus_round_timer, ram.consensus.nextsleep) 
    }
    consensus_round_timer()

}
