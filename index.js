const { ArgumentParser } = require('argparse')
const crypto = require('crypto')
const net = require('net')

const PROTO_ABRIDGED = Buffer.from('efefefef', 'hex')
const PROTO_INTERMEDIATE = Buffer.from('eeeeeeee', 'hex')
const PROTO_SECURE = Buffer.from('dddddddd', 'hex')

const parser = new ArgumentParser({
    addHelp: true,
    description: 'MTProxy Protocol Simulator'
})

parser.addArgument(
    ['-p', '--simulateReqPq'],
    {
        help: 'Simulate reqPQ',
        action: 'storeTrue',
        nargs: 0
    }
)

parser.addArgument(
    ['-ps', '--simulateServerPadding'],
    {
        help: 'Simulate Server-side req_pq Padding',
        action: 'storeTrue',
        nargs: 0
    }
)

parser.addArgument(
    ['-psl', '--simulateServerPaddingLarge'],
    {
        help: 'Simulate Server-side req_pq Padding (Large)',
        action: 'storeTrue',
        nargs: 0
    }
)

parser.addArgument('type', {
    help: 'Working type',
    choices: ['client', 'server']
})
parser.addArgument('protocol', {
    help: 'Protocol to simulate',
    choices: ['abridged', 'intermediate', 'secure']
})
parser.addArgument('host')
parser.addArgument('port', {
    type: Number
})

parser.addArgument('secret')

const args = parser.parseArgs()
console.dir(args)

if (args.type === 'client') {
    handleClient(args)
} else {
    handleServer(args)
}

function handleClient(args) {
    const { host, port, secret, simulateReqPq, protocol, simulateServerPadding, simulateServerPaddingLarge } = args
    const secbin = Buffer.from(secret, 'hex')

    const encprekey = crypto.randomBytes(32)
    const enciv = crypto.randomBytes(16)
    const enc_key = crypto.createHash('sha256').update(Buffer.concat([encprekey, secbin])).digest()

    const revmix = Buffer.concat([encprekey, enciv]).reverse()
    const decprekey = revmix.slice(0, 32)
    const deciv = revmix.slice(32, 48)
    const dec_key = crypto.createHash('sha256').update(Buffer.concat([decprekey, secbin])).digest()

    let protocol_flag
    switch (protocol) {
        case 'abridged': 
            protocol_flag = PROTO_ABRIDGED
            break
        case 'intermediate': 
            protocol_flag = PROTO_INTERMEDIATE
            break
        case 'secure': 
            protocol_flag = PROTO_SECURE
            break
    }

    const dc_idx = Math.floor(Math.random() * 4) + 1
    const dc_idx_buf = Buffer.allocUnsafe(2).fill(0)
    dc_idx_buf.writeUInt8(dc_idx)

    const handshake_pkg = Buffer.concat([crypto.randomBytes(8), encprekey, enciv, protocol_flag, dc_idx_buf, Buffer.from('0000', 'hex')])
    const encryptor = crypto.createCipheriv('aes-256-ctr', enc_key, enciv)
    const decryptor = crypto.createDecipheriv('aes-256-ctr', dec_key, deciv)

    const encrypted_handshake_pkg = encryptor.update(handshake_pkg)
    const real_handshake_pkg = Buffer.concat([handshake_pkg.slice(0, 56), encrypted_handshake_pkg.slice(56, 64)])

    const client = net.connect(port, host)

    client.on('ready', () => {
        const auth_key_id = Buffer.allocUnsafe(8).fill(0)
        const msg_id = crypto.randomBytes(32)

        console.log('Encrypt key:', enc_key.toString('hex'))
        console.log('Encrypt IV:', enciv.toString('hex'))
        console.log('Decrypt key:', dec_key.toString('hex'))
        console.log('Encrypt IV:', deciv.toString('hex'))
        console.log('Protocol:', protocol)
        
        let msg
        if (simulateReqPq) {
            const padding_length = simulateServerPaddingLarge ? Math.floor(Math.random() * 256) : Math.floor(Math.random() * 16)
            const length = simulateServerPadding ? 16 + padding_length - padding_length % 4 : 16
            msg = Buffer.concat([Buffer.from('1400000078974660', 'hex'), crypto.randomBytes(length)])
            console.log('Compositing req_pq')
        } else {
            const msg_length = Math.floor(Math.random() * 2048) + 32
            msg = crypto.randomBytes(msg_length)
        }


        const data_pack = Buffer.concat([auth_key_id, msg_id, msg])
        if (protocol === 'intermediate') {
            const data_length = Buffer.allocUnsafe(4).fill(0)
            data_length.writeUInt32LE(data_pack.length)
            const data = Buffer.concat([data_length, data_pack])
            const enc_data = encryptor.update(data)
            const pack = Buffer.concat([real_handshake_pkg, enc_data])

            console.log('Send', pack.length - 64, 'bytes')
            client.write(pack)
        } else if (protocol === 'secure') {
            const data_length = Buffer.allocUnsafe(4).fill(0)
            data_length.writeUInt32LE(data_pack.length)
            const data = Buffer.concat([data_length, data_pack])
            const enc_data = encryptor.update(data)
            const padding_length = Math.floor(Math.random() * 2.99) + 1
            const padding = crypto.randomBytes(padding_length)
            const pack = Buffer.concat([real_handshake_pkg, enc_data, padding])

            console.log('Send', pack.length - 64, 'bytes')
            client.write(pack)
        } else if (protocol === 'abridged') {
            let data_length
            if (data_pack.length < 128) {
                data_length = Buffer.allocUnsafe(1).fill(0)
                data_length.writeUInt8(data_pack.length)
            } else {
                data_length = Buffer.allocUnsafe(4).fill(0)
                data_length.writeUInt32LE(data_pack.length)
                data_length = Buffer.concat([Buffer.from('7f', 'hex'), data_length.slice(1)])
            }

            const data = Buffer.concat([data_length, data_pack])
            const enc_data = encryptor.update(data)
            const pack = Buffer.concat([real_handshake_pkg, enc_data])

            console.log('Send', pack.length - 64, 'bytes')
            client.write(pack)
        }

    })

    client.on('data', (chunk) => {
        if (protocol === 'secure') {
            const offset = chunk.length % 4
            chunk = chunk.slice(0, chunk.length - offset)
        }
        let raw_data = decryptor.update(chunk)
        if (protocol === 'abridged') {
            if (raw_data.slice(0, 1).equals(Buffer.from('7f', 'hex'))) {
                raw_data = raw_data.slice(4)
            } else {
                raw_data = raw_data.slice(1)
            }
        } else if (protocol === 'intermediate' || protocol === 'secure') {
            raw_data = raw_data.slice(4)
        }
        const res_str = raw_data.toString('hex')
        console.log('Received', raw_data.length, 'bytes')
        const auth_key_id = Buffer.allocUnsafe(8).fill(0)
        const msg_id = crypto.randomBytes(32)

        let msg
        if (res_str.indexOf('4000000063241605') > -1) {
            const padding_length = simulateServerPaddingLarge ? Math.floor(Math.random() * 256) : Math.floor(Math.random() * 16)
            const length = simulateServerPadding ? 316 + padding_length - padding_length % 4 : 316
            msg = Buffer.concat([Buffer.from('40010000BEE412D7', 'hex'), crypto.randomBytes(length)])
            console.log('Received res_pq, Compositing req_DH_params')
        } else if (res_str.indexOf('780200005c07e8d0') > -1) {
            const padding_length = simulateServerPaddingLarge ? Math.floor(Math.random() * 256) : Math.floor(Math.random() * 16)
            const length = simulateServerPadding ? 372 + padding_length - padding_length % 4 : 372
            msg = Buffer.concat([Buffer.from('780100001F5F04F5', 'hex'), crypto.randomBytes(length)])
            console.log('Received server_DH_params_ok, Compositing set_client_DH_params')
        } else {
            if (res_str.indexOf('3400000034f7cb3b') > -1) console.log('Received dh_gen_ok')
            const msg_length = Math.floor(Math.random() * 2048) + 32
            msg = crypto.randomBytes(msg_length)
        }


        const data_pack = Buffer.concat([auth_key_id, msg_id, msg])
        if (protocol === 'intermediate') {
            const data_length = Buffer.allocUnsafe(4).fill(0)
            data_length.writeUInt32LE(data_pack.length)
            const data = Buffer.concat([data_length, data_pack])
            const enc_data = encryptor.update(data)
            const pack = enc_data
            console.log('Send', pack.length, 'bytes')
            client.write(pack)
        } else if (protocol === 'secure') {
            const data_length = Buffer.allocUnsafe(4).fill(0)
            data_length.writeUInt32LE(data_pack.length)
            const data = Buffer.concat([data_length, data_pack])
            const enc_data = encryptor.update(data)
            const padding_length = Math.floor(Math.random() * 2.99) + 1
            const padding = crypto.randomBytes(padding_length)
            const pack = Buffer.concat([enc_data, padding])
            console.log('Send', pack.length, 'bytes')
            client.write(pack)
        } else if (protocol === 'abridged') {
            let data_length
            if (data_pack.length < 128) {
                data_length = Buffer.allocUnsafe(1).fill(0)
                data_length.writeUInt8(data_pack.length)
            } else {
                data_length = Buffer.allocUnsafe(4).fill(0)
                data_length.writeUInt32LE(data_pack.length)
                data_length = Buffer.concat([Buffer.from('7f', 'hex'), data_length.slice(1)])
            }
            const data = Buffer.concat([data_length, data_pack])
            const enc_data = encryptor.update(data)
            const pack = enc_data
            console.log('Send', pack.length, 'bytes')
            client.write(pack)
        }
    })

    client.on('end', () => {
        try {
            encryptor.final()
            decryptor.final()
        } catch (e) {
            //ignore
        }
    })

    client.on('error', e => {
        try {
            encryptor.final()
            decryptor.final()
        } catch (e) {
            //ignore
        }
        console.error(e)
        client.destroy()
    })

}

function handleServer(args) {
    const { host, port, secret, simulateServerPadding, simulateServerPaddingLarge } = args
    const secbin = Buffer.from(secret, 'hex')

    const server = net.createServer(socket => {
        socket.handshake = false

        socket.on('data', (chunk) => {
            if (!socket.handshake) {
                const handshake_pkg = chunk.slice(0, 64)
                const decprekeyiv = handshake_pkg.slice(8, 8 + 32 + 16)
                const decprekey = decprekeyiv.slice(0, 32)
                const deciv = decprekeyiv.slice(32, 32 + 16)
                const deckey = crypto.createHash('sha256').update(Buffer.concat([decprekey, secbin])).digest()

                const encprekeyiv = Buffer.from(decprekeyiv).reverse()
                const encprekey = encprekeyiv.slice(0, 32)
                const enciv = encprekeyiv.slice(32, 32 + 16)
                const enckey = crypto.createHash('sha256').update(Buffer.concat([encprekey, secbin])).digest()

                socket.encryptor = crypto.createCipheriv('aes-256-ctr', enckey, enciv)
                socket.decryptor = crypto.createDecipheriv('aes-256-ctr', deckey, deciv)

                /** @type {Buffer} */
                const plainhandshake = socket.decryptor.update(handshake_pkg)
                const proto_tag = plainhandshake.slice(56, 56 + 4)
                
                if (proto_tag.equals(PROTO_ABRIDGED)) {
                    socket.protocol = 'abridged'
                } else if (proto_tag.equals(PROTO_INTERMEDIATE)) {
                    socket.protocol = 'intermediate'
                } else if (proto_tag.equals(PROTO_SECURE)) {
                    socket.protocol = 'secure'
                } else {
                    socket.destroy(new Error('Unknown protocol'))
                }

                const dc_idx_buf = plainhandshake.slice(60, 60 + 2)
                const dc_idx = dc_idx_buf.readUInt8()
                socket.dc_idx = dc_idx

                console.log('Incoming connection')
                console.log('Encrypt key:', enckey.toString('hex'))
                console.log('Encrypt IV:', enciv.toString('hex'))
                console.log('Decrypt key:', deckey.toString('hex'))
                console.log('Decrypt IV:', deciv.toString('hex'))
                console.log('Protocol:', socket.protocol)
                console.log('DC Id:', dc_idx)
                
                socket.handshake = true

                chunk = chunk.slice(64)
            }

            if (socket.protocol === 'secure') {
                const offset = chunk.length % 4
                chunk = chunk.slice(0, chunk.length - offset)
            }

            let raw_data = socket.decryptor.update(chunk)
            if (socket.protocol === 'abridged') {
                if (raw_data.slice(0, 1).equals(Buffer.from('7f', 'hex'))) {
                    raw_data = raw_data.slice(4)
                } else {
                    raw_data = raw_data.slice(1)
                }
            } else if (socket.protocol === 'intermediate' || socket.protocol === 'secure') {
                raw_data = raw_data.slice(4)
            }

            const res_str = raw_data.toString('hex')
            console.log('Received', chunk.length, 'bytes')
            const auth_key_id = Buffer.allocUnsafe(8).fill(0)
            const msg_id = crypto.randomBytes(32)

            let msg
            if (res_str.indexOf('1400000078974660') > -1) {
                const padding_length = simulateServerPaddingLarge ? Math.floor(Math.random() * 256) : Math.floor(Math.random() * 16)
                const length = simulateServerPadding ? 60 + padding_length - padding_length % 4 : 60
                msg = Buffer.concat([Buffer.from('4000000063241605', 'hex'), crypto.randomBytes(length)])
                console.log('Received req_pq, Compositing res_pq')
            } else if (res_str.indexOf('40010000bee412d7') > -1) {
                const padding_length = simulateServerPaddingLarge ? Math.floor(Math.random() * 256) : Math.floor(Math.random() * 16)
                const length = simulateServerPadding ? 628 + padding_length - padding_length % 4 : 628
                msg = Buffer.concat([Buffer.from('780200005C07E8D0', 'hex'), crypto.randomBytes(length)])
                console.log('Received req_DH_params, Compositing server_DH_params_ok')
            } else if (res_str.indexOf('780100001f5f04f5') > -1) {
                const padding_length = simulateServerPaddingLarge ? Math.floor(Math.random() * 256) : Math.floor(Math.random() * 16)
                const length = simulateServerPadding ? 48 + padding_length - padding_length % 4 : 48
                msg = Buffer.concat([Buffer.from('3400000034F7CB3B', 'hex'), crypto.randomBytes(length)])
                console.log('Received set_client_DH_params, Compositing dh_gen_ok')
            } else {
                const msg_length = Math.floor(Math.random() * 2048) + 32
                msg = crypto.randomBytes(msg_length)
            }

            const data_pack = Buffer.concat([auth_key_id, msg_id, msg])
            if (socket.protocol === 'intermediate') {
                const data_length = Buffer.allocUnsafe(4).fill(0)
                data_length.writeUInt32LE(data_pack.length)
                const data = Buffer.concat([data_length, data_pack])
                const enc_data = socket.encryptor.update(data)
                const pack = enc_data
                console.log('Send', pack.length, 'bytes')
                socket.write(pack)
            } else if (socket.protocol === 'secure') {
                const data_length = Buffer.allocUnsafe(4).fill(0)
                data_length.writeUInt32LE(data_pack.length)
                const data = Buffer.concat([data_length, data_pack])
                const enc_data = socket.encryptor.update(data)
                const padding_length = Math.floor(Math.random() * 2.99) + 1
                const padding = crypto.randomBytes(padding_length)
                const pack = Buffer.concat([enc_data, padding])
                console.log('Send', pack.length, 'bytes')
                socket.write(pack)
            } else if (socket.protocol === 'abridged') {
                let data_length
                if (data_pack.length < 128) {
                    data_length = Buffer.allocUnsafe(1).fill(0)
                    data_length.writeUInt8(data_pack.length)
                } else {
                    data_length = Buffer.allocUnsafe(4).fill(0)
                    data_length.writeUInt32LE(data_pack.length)
                    data_length = Buffer.concat([Buffer.from('7f', 'hex'), data_length.slice(1)])
                }
                const data = Buffer.concat([data_length, data_pack])
                const enc_data = socket.encryptor.update(data)
                const pack = enc_data
                console.log('Send', pack.length, 'bytes')
                socket.write(pack)
            }
        })

        socket.on('end', () => {
            try {
                socket.encryptor.final()
                socket.decryptor.final()
            } catch (e) {
                //ignore
            }
        })

        socket.on('error', e => {
            try {
                socket.encryptor.final()
                socket.decryptor.final()
            } catch (e) {
                //ignore
            }
            console.error(e)
            socket.destroy()
        })
    })

    server.listen(port, host)
}
