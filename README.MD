# Hot Pocket Prototype
## What is this?
Hot Pocket (HP) is a consensus engine for any collection of linux or mac machines and/or Codius.

Given an arbitrary binary (i.e. virtually any program) HP will perform consensus on its inputs and state and outputs in a way that is user centric, building its own verifiable chain of executions to which each HP node in your network has agreed.

## Smart Contract Interface
The programmer (you) supplies a binary aka a smart contract (SC), around which you will build a HP network. Your network begins with a genesis ledger. Each consensus round between your nodes builds on the last ledger, forming a chain of ledgers. If a node leaves and rejoins it can re-enter consensus by catching up missing history and copying state from a peer.

To facilitate communication between your SC and the outside world, HP will open file descriptors before executing your SC. When your SC starts it will receive a list of public keys and file descriptors on stdin which tell it which user is associated with which file descriptor.

At time of writing the format is json in the form below

Example
```
{
 "hotpocket": 0.1,
 "lcl": "f8ee60b3c87bcd6c8c144f0e87ffef0c70debca78a4f85d7508dee71dd68d551",
 "mver": 1,
 "npl": [
  29,
  28
 ],
 "pubkey": "7043a21ab5487895c1ee36dc6a3ef4714f356ff1a45b299a8c1d285129638597",
 "time": "1568193881",
 "type": "binexec",
 "unl": [
  "7043a21ab5487895c1ee36dc6a3ef4714f356ff1a45b299a8c1d285129638597"
 ],
 "user": {
  "703a9da32528c2b270c0795987a13a37777776eb6ea8ac24fcb448ce1cce20af": [
   33,
   32
  ]
 }
}
```

Your SC should read and parse this list from stdin and then read and write from the user's specific fd's according to your SC's desire or need to communicate with those users. Whenever there is an array of fds, the 0th entry is the input fd and the 1st entry is the output directory. So for example to talk to the user whose public key is `703a9da32528c2b270c0795987a13a37777776eb6ea8ac24fcb448ce1cce20af` above we would write output to FD 32. If we wanted to read any input they had sent us we would read from FD 33.


## User Connections

Users connect via websocket to any HP node in your network (running your SC). You specify what public port (if any) your node/s listen on in the contract config under `cfg/hp.cfg`.

The node a user is connected to is responsible for maintaining the user's connection. That node is also responsible for collecting input from the user, and circulating that input into the consensus algorithm, and collecting outputs destined for that user (from the outcome of consensus) and routing those outputs to that user.

When a user connects to a HP node it is sent a `public_challenge` message:
```
{
hotpocket: 0.1,
type: 'public_challenge',
challenge: 'ef97b2286de21927d48cc54fcab401c3'
}
```


A valid response is simply to nominate a public key and then use it to sign a message containing the random challenge code, and supply the signature.

E.g. a valid `helo` response to the above looks like:
```
{
sig: 'b987cc7662b1a3af54341b06069ba6603af4f76d9186860d243787c55530c8d5fa5a3c000fbeaabb662ed0b17c135a92632daf89421017a4a74e1cb00e0ca109',
pubkey: 'f9dc8c751cabf82d64325a50ff3ec6b68058af565326efa8bb1eb5f4a34a43a8',
timestamp: 1567852562,
challenge: 'ef97b2286de21927d48cc54fcab401c3',
type: 'helo'
}
```

Now the challenge/response handshake is completed the user is dropped into a binary mode. Anything sent to the node will be circulated into the consensus and executed simultaneously on all HP nodes in the network. The output will be processed through a second consensus round and the binary output will be fed back out through the same websocket to the user.

`hp_client.js` provides an example client for connecting to HP networks.

## Node Party Line
Two FDs are provided in the fdlist under the npl key. These access what's called the node party line. This is effectively a realtime communication channel shared by all nodes connected to your HP network. The purpose of this channel is to allow nodes to perform multisigning and other tasks that require each node to behave as an individual rather than a perfectly deterministic clone of every other node. So for example 4 nodes with 4 keys could all sign a message and convey to eachother their signatures over the node party line. Once all signatures are collected all 4 nodes can agree on an order and a canonical transaction with 4 signatures attached to it.

To read messages from the NPL use the 0th FD. The format of messages on the 0th FD is similar to HTTP response header (except no \r):
```
Length: 1031\n
Pubkey: deadbeefdeadbeefdeadbeef\n\n
<raw message data>
```

To send a message to the NPL write to the 1st FD any data you desire, the HP controller will encode and transmit it to all connected peers and they will replicate it to their peers.


## Prototype Warning
This project is in a very early prototype. It definitely should not be used for any production application at this time. In particular TLS has not yet been added to HP messages. Also there are likely to be consensus bugs as most testing so far as been on a single physical device.

## Requirements
 - linux or macos
 - node
 - npm
 - gcc
 
## Usage
An example contract is provided. To run it simply run `./run-test-contract` from linux or macos. Warning: please download the RELEASE, not the latest commit to run this example, as the fdlist format has changed.
