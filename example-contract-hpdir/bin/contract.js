/**
    HpDir -- A Hot Pocket smart contract to provide directory services
             for other smart contracts

    Name scheme: hp.<category>.<your smart contract name here>

    Categories are free form but help users find your smart contract          

    Usage:  1. connect to a valid hpdir node
            2. issue a C/U/D command as follows:
               { 'cmd': 'create|update|delete', 
                 'name': 'hp.fin.acmebank',    // required for every cmd
                 'unl': '[<pubkeyhex>, ...]',  // optional on upd, del
                 'peer': [ ip:port, ...]      // optional on upd, del
                 'pubkey': <pubkeyhex>         // optional on create,del [entry owner]
               }

            3. expected C/U/D response
               { 'success': true|false }

            4. issue a READ command as follows:
               { 'cmd': 'read',
                 'name': 'hp.fin.acmebank'}

            5. expected READ response
               { 'success': true|false,
                 'unl': [<pubkeyhex>, ...],
                 'peers': [ ip:port, ... ],
                 'pubkey': <pubkeyhex> }

**/
const fs = require('fs')
const pipe = require('posix-pipe-fork-exec')

var rom = Buffer.from(pipe.getfdbytes(0)).toString()
try {
    rom = JSON.parse(rom)
} catch (e) {
    console.log('invalid contract input')
    process.exit(1)
}

for (var user in rom.user) {
    
    // fd[0] is our reading fd, fd[1] is our writing fd
    var fd = rom.user[user]    

    var input = Buffer.from(pipe.getfdbytes(fd[0])).toString()
    console.log('user input: ' + input)
    if (input) {
        process_user_input(user, fd[0], fd[1], input)
    }
}


function process_user_input(user, fdin, fdout, inp) {
    var error = (info) => {
        fs.writeSync(fdout, JSON.stringify(
            {success: false, info: (typeof(info) == 'string' ? info : '' + info)}))
    }
    
    var success = (info, more) => {
        var resp = {success: true}
        if (info) resp.info = info
        if (more) for (var k in more) resp[k] = more[k]
        fs.writeSync(fdout, JSON.stringify(resp))
    }

    if (!inp) return

    try {
        inp = JSON.parse(inp)
    } catch (e) {
        return error('malformed request')
    }

    if (!inp.cmd) return error('missing key `cmd`')    
    if (!inp.name || typeof(inp.name) != 'string') return error('missing key `name`')
    
    var fn = 'state/' + Buffer.from(inp.name).toString('hex')

    if (inp.cmd == 'create') {

        if (!inp.unl) return error('missing key `unl`')
        if (!inp.peer) return error('missing key `peer`')

        // check if name follows the rules
        if (inp.name.length > 30) 
            return error('name is too long, must be <= 30 characters')

        if (!inp.name.match(/^hp.[a-z0-9\-]+\.[a-z0-9\-\.]+$/))
            return error('name must be in the convention hp.category.name')

        // check if the entry exists
        if (fs.existsSync(fn)) return error('name is taken')
        
        // execution to here means name is not taken
        // strip out unwanted keys and save their req as the entry
        delete inp.cmd

        // ensure a key is being saved
        if (!inp.pubkey)
            inp.pubkey = user

        try {
            fs.writeFileSync(fn, JSON.stringify(inp)) 
        } catch (e) { 
            return error(e)
        }

        return success('name was created')

    } else if (inp.cmd == 'update') {

        // at least one of unl, peer, pubkey must be set
        if (! (inp.unl || inp.peer || inp.pubkey) )
            return error('update must specify unl, peer or pubkey to update')

        // read existing
        try {
            var entry = JSON.parse(fs.readFileSync(fn))
            if (user != entry.pubkey)
                return error('you are not authorized to change this name')

            if (inp.unl) entry.unl = inp.unl
            if (inp.peer) entry.peer = inp.peer
            if (inp.pubkey) entry.pubkey = inp.pubkey
            fs.writeFileSync(fn, JSON.stringify(entry))

            return success('name was updated')

        } catch (e) {
            return error('the name doesn\'t exist, or record is malformed')
        } 

    } else if (inp.cmd == 'delete') {
        try {
            var entry = JSON.parse(fs.readFileSync(fn))
            if (user != entry.pubkey)
                return error('you are not authorized to change this name')

            fs.unlinkSync(fn)
            return success('name was deleted')

        } catch (e) {
            return error('the name doesn\'t exist, or record is malformed')
        } 

    } else if (inp.cmd == 'read') {
        try {
            var entry = JSON.parse(fs.readFileSync(fn))
            return success(false, entry)
        } catch (e) {
            return error('the name doesn\'t exist, or record is malformed')
        } 
    } else {
        return error('invalid cmd, try one of: create, update, delete, read')
    }

}

/*

     {
       "hotpocket": 0.1,
       "type": "binexec",
       "mver": 1,
       "time": "1568119132",
       "pubkey": "7043a21ab5487895c1ee36dc6a3ef4714f356ff1a45b299a8c1d285129638597",
       "unl": [
         "7043a21ab5487895c1ee36dc6a3ef4714f356ff1a45b299a8c1d285129638597"
       ],
       "npl": [
         0,
         1
       ],
       "user": {
            "test": [0, 1]
        },
       "lcl": ""
     }

*/


