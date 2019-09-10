const fs = require('fs')
const pipe = require('posix-pipe-fork-exec')


// process the fdlist first
var fdlist = ""
process.stdin.on('data', function(chunk) {
    fdlist += chunk
});

process.stdin.on('end', function() {
    try {
        fdlist = JSON.parse(fdlist)
        contract()
    } catch (e) {
        console.log(e)
        process.exit(1)
    }
});


function contract() {
   
    for (var user in fdlist.user) {
        console.log("bytes for user " + user + " = " + new Buffer(pipe.getfdbytes(fdlist.user[user][0])).toString())
        fs.writeSync(fdlist.user[user][1], "wrote you some bytes, " + user) 
    } 
    process.exit(0)
}


