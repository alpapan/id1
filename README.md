
# id1: all-in-one backend for everything  
> API, identity and access, storage, messaging, scheduling, integration  
> 9 MB executable, 0.5 Ghz CPU, 15 MB RAM, sub 1 ms latency

## How to build

Docker image

    $ docker build -t id1:latest .
    $ docker run --rm -d -p 8080:8080 --mount type=volume,src=id1db,dst=/mnt/id1db --name id1 id1:latest

Executable

    func main() {
        ctx := context.Background()
        handle := id1.Handle(dbpath, ctx)
        http.HandleFunc("/{key...}", func(w http.ResponseWriter, r *http.Request) {
            handle(w, r)
        })
        http.ListenAndServe(":8080", nil)
        ctx.Done()
    }

optional .env file

    PORT=8080
    DBPATH=id1db

## Commands
All communication is done using id1 commands.
Commands have operation, key, arguments and data.

Message format:

    <operation[get|set|add|mov|del|list]>:/<key>?<arguments>
    [data....]

For HTTP bridge, method is operation, path is key, params are options, body is data.  

Operation "get" with key ending with * accepts list arguments:

    recursive=[true|false]
    children=[true|false]
    keys=[true|false]
    limit=[n]
    size-limit=[n]
    total-size-limit=[n]

Each numeric list argument has a ceiling: limit 1000, and size-limit and total-size-limit 100 MiB each. A value above its ceiling, a negative value, or a value that is not a number is replaced by the ceiling.

## Identity and Access Management
id1 account is an RSA public key in [dir]/pub/key (a service identity) or in [dir]/pub/keys/[device] (one per device). If either exists then [dir] is an account id authenticated with the matching private key. The authentication challenge is built from [dir]/pub/keys/[device] (device from the device argument, default "default"); an account with only [dir]/pub/key gets 404.
Key pair is user generated, private key never shared.

#### Authentication
Requests and sessions authenticated with a JWT token signed using server generated secret. 
Requests without a valid JWT token return authentication challenge. Challenge is the signing secret encrypted with account's public key. 
Whoever has the private key can decrypt the secret and use it to sign tokens. Secrets generated as hash of id, time and a random string.

#### Authorisation
Account owner has full access to account dir, i.e. can execute any operation on keys that start with [id]/, except that mov refuses a source key under [id]/priv/.  
Everyone has read access to [id]/pub, i.e. can execute get on keys that start with [any]/pub/.  
If request is authenticated but command is not authorised, 403 is returned.

#### Dot Op files: .get, .set, .add, .mov .del
To authorise an operation on a key path (folder), create a .[op] file containing ids authorised for the operation.
For example, to authorise everyone to write (but not read or delete) to admin/msg, set admin/msg/.set to "*".
To authorise user "max" to read and delete, add line "max" to admin/msg/.set and admin/msg/.del  

#### Roles with .roles
To assing roles (id aliases) in effect under a key path, create .roles/[id] with roles as line separated values.

For example, setting admin/.roles/monty to "max" will give "monty" same rights under admin/ as "max".
Adding roles like "User" or "Member" to .[op] files and listing the roles in .roles/[id] is the default way of managing privileges.

A role granted through a .[op] file or .roles/[id] never reaches a key under [id]/priv/, a control file (a key whose last segment is "." followed by an operation name, such as .set) or anything inside a .roles directory; delegation never grants these. Public read of [id]/pub does not depend on delegation, so control and .roles files placed under [id]/pub are readable by everyone. .roles files are read only below the store root, never at it.

A delegated set, add, del or mov also never reaches the owner's key files, [id]/pub/key and [id]/pub/keys/..., or the [id]/pub and [id]/pub/keys directory paths themselves; other keys under [id]/pub stay delegable. The account owner is not restricted by this rule.

mov refuses a source key in the owner's private subtree [id]/priv/..., whoever asks, the owner included.

## Messaging
Authenticating a websocket session will subscribe the session to account change events. 
For example, if a key

    admin/msg/max/1745000022345
    
was set, all sessions authenticated as "admin" will receive command

    set:/admin/msg/max/1745000022345
    
If the key was deleted, sessions will receive

    del:/admin/msg/max/1745000022345

## Scheduling and TTL
Set a .after.[timestamp] key containing a command to be executed soon after [timestamp] (milliseconds).

Adding option "ttl" to a set command will create a .after.(ttl seconds from now) with delete command for the key.

## Command Examples

#### CRUD flow

    set:/path/to/key
    Always look on the...
    
    add:/path/to/key
    ...bright side of life

    mov:/path/to/key
    path/to/another/key

    get:/path/to/another/key

    del:/path/to/another/key

    get:/path/to/*
    
#### Curl

    curl -X POST https://api.id1.au/max/msg/monty/1745000011111?ttl=86400 -d "Hello"  -H "Authorization: Bearer <token>"
    
    curl https://api.id1.au/max/msg/\*\?size-limit=1024\&limit=10  -H "Authorization: Bearer <token>"
    
    curl -X PATCH https://api.id1.au/max/msg/monty/1745000011111 -H "X-Move-To: max/arc/monty/1745000011111" -H "Authorization: Bearer <token>"
    
    curl -X DELETE https://api.id1.au/max/msg/monty/1745000011111 -H "Authorization: Bearer <token>"


#### Recursively list up to 100 key/value pairs with value size under 1kb

    get:/path/to/*?recursive=true&limit=100&size-limit=1024

#### List keys only
    
    get:/path/to/*?keys=true
    
#### List key names and key path names

    get:/path/to/*?children=true

#### Schedule a reminder 

    set:/max/.after.1745000011111
    set:/max/reminders/reminder1?ttl=60
    Reminder: Always look on the bright side of life

#### Schedule create, archive, delete

    set:/max/.after.1745000011111
    set:/max/msg/monty/1745000011111
    Always look on the bright side of life
  
    set:/max/.after.1745000022222
    mov:/max/msg/monty/1745000011111
    max/arc/monty/1745000011111?ttl=86400
    
#### Chat flow

    <- set:/monty/msg/max/1745000011111
    Hi Monty
  
    -> set:/max/msg/monty/1745000022222
    Hi Max

    <- mov:/max/msg/monty/1745000022222
    max/arc/msg/monty/1745000022222

    <- set:/monty/msg/max/1745000033333
    What are you up to?

    -> set:/max/msg/monty/1745000044444
    Just hanging around.. and up to something..
