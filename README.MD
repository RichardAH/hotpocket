# Hot Pocket Prototype
## What is this?
Hot Pocket (HP) is a consensus engine for Codius.

Given an arbitrary binary (i.e. virtually any program) HP will perform consensus on its inputs and state and outputs in a way that is user centric, building its own verifiable chain of executions to which each HP node in your network has agreed.

## Smart Contract Interface
The programmer (you) supplies a binary aka a smart contract (SC), around which you will build a HP network. Your network begins with a genesis ledger. Each consensus round between your nodes builds on the last ledger, forming a chain of ledgers. If a node leaves and rejoins it can re-enter consensus by catching up missing history and copying state from a peer.

To facilitate communication between your SC and the outside world, HP will open file descriptors before executing your SC. When your SC starts it will receive a list of public keys and file descriptors on stdin which tell it which user is associated with which file descriptor.

At time of writing the format is: `<hex public key>=<read fd>:<write fd>`

Example
```
HOTPOCKET 0.1
f9dc8c751cabf82d64325a50ff3ec6b68058af565326efa8bb1eb5f4a34a43a8=30:29
0be7424e59eacbe624ac82bbe2cc9e72afc8a770930396a3a4f059e7a5a3aa81=34:33
```
However note that this format is likely to change to a JSON format in the future.

Your SC should read and parse this list from stdin and then read and write from the user's specific fd's according to your SC's desire or need to communicate with those users.

## User Connections

Users connect via websocket to any HP node in your network (running your SC). You specify what public port (if any) your node/s listen on in the contract config under `cfg/hp.cfg`.

The node a user is connected to is responsible for maintaining the user's connection. That node is also responsible for collecting input from the user, and circulating that input into the consensus algorithm, and collecting outputs destined for that user (from the outcome of consensus) and routing those outputs to that user.

When a user connects to a HP node it is sent a `public_challenge` message:
```{
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


## Prototype Warning
This project is in a very early prototype. It definitely should not be used for any production application at this time. In particular TLS has not yet been added to HP messages.

## Requirements
 - linux or macos
 - node
 - gcc
 
## Usage
An example contract is provided. To run it simply run `./run-test-contract` from linux or macos
