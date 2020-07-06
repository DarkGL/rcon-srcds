const { createConnection } = require('net');
const Packet = require('./packet');
const Protocol = require('./protocol');
const queue = require('queue');

/**
 * @typedef {Object} ClassOptions 
 * @property {string} [host='127.0.0.1'] Server port
 * @property {number} [port=27015] Server port
 * @property {number} [maximumPacketSize=4096] Maximum packet bytes size, zero to unlimit
 * @property {('ascii'|'utf8')} [encoding='ascii'] Socket encoding
 * @property {number} [timeout=1000] Socket timeout (ms)
 */

/**
 * Source RCON (https://developer.valvesoftware.com/wiki/Source_RCON)
 */
class SourceRCON {
    /**
     * @param {ClassOptions} [options] 
     */
    constructor (options = {}) {
        /**
         * Server port
         * @type {string}
         * @default '127.0.0.1'
         */
        this.host = options.host || '127.0.0.1';

        /**
         * Server port
         * @type {number}
         * @default 27015
         */
        this.port = options.port || 27015;

         /**
         * Local address
         * @type {string}
         * @default 0.0.0.0
         */
        this.localAddress = options.localAddress || '0.0.0.0';

        /**
         * Maximum packet bytes size, zero to unlimit
         * @type {number}
         * @default 4096
         */
        this.maximumPacketSize = options.maximumPacketSize || 4096; // https://developer.valvesoftware.com/wiki/Source_RCON#Packet_Size
        
        /**
         * Socket encoding
         * @type {('ascii'|'utf8')}
         * @default 'ascii'
         */
        this.encoding = options.encoding || 'ascii';

        /**
         * Socket timeout (ms)
         * @type {number}
         * @default 1000
         */
        this.timeout = options.timeout || 1000;

        /**
         * Socket connection
         * @type {net.Socket}
         */
        this.connection = createConnection({
            host: this.host,
            port: this.port,
            localAddress: this.localAddress,
        });

        this.connection.setTimeout(this.timeout);

        this.connection.on('data', this.onData.bind( this ));
        this.connection.once('error', this.onError.bind( this ));

        /**
         * Whether server has been authenticated
         * @type {boolean}
         * @default false
         * @private
         */
        this.authenticated = false;

        this.packetResponseCallback = {};

        this.responseAck = {};

        this.responseExecute = {};

        this.authRequest = 0;
    }

    onData( packet ) {
        const decodedPacket = Packet.decode(packet, this.encoding);

        if( decodedPacket.type === Protocol.SERVERDATA_RESPONSE_VALUE ){
            if( this.responseAck[ decodedPacket.id ] && decodedPacket.body === '\x00\x01\x00\x00' ){
                this.packetResponseCallback[ this.responseAck[ decodedPacket.id ].id ]( this.responseExecute[ this.responseAck[ decodedPacket.id ].id ] );

                delete this.responseAck[ decodedPacket.id ];
                delete this.packetResponseCallback[ this.responseAck[ decodedPacket.id ] ];
                delete this.responseExecute[ decodedPacket.id ];
            }
            else if( this.responseAck[ decodedPacket.id ] ){
                this.responseExecute[ decodedPacket.id ] = this.responseExecute[ decodedPacket.id ].concat(decodedPacket.body.replace(/\n$/, '\n'));
            }
        }
        else if( decodedPacket.type === Protocol.SERVERDATA_AUTH_RESPONSE){
            if( decodedPacket.id === -1 ){

                this.packetResponseCallback[ this.authRequest ]( false );

                this.authRequest = 0;

                return;
            }

            this.packetResponseCallback[ this.authRequest ]( true );

            this.authRequest = 0;
        }
    }

    onError() {

    }

    /**
     * Authenticate to server
     * @param {string} password
     * @returns {Promise<void>}
     */
    authenticate (password) {
        return new Promise((resolve, reject) => {
            if (this.authenticated)
                reject(Error('Already authenticated'))

            // Send a authentication packet (0x02)
            this.write(Protocol.SERVERDATA_AUTH, Protocol.ID_AUTH, password)
                .then((data) => {
                    if (data) {
                        this.authenticated = true;
                        resolve();
                    } else {
                        this.disconnect();

                        reject(Error('Unable to authenticate'));
                    }
                })
                .catch(reject);

            setTimeout( reject, 5000 );
        });
    }

    /**
     * Disconnect from server and destroy socket connection
     * @returns {Promise<void>}
     */
    disconnect () {
        this.authenticated = false;
        this.connection.destroy();

        return new Promise((resolve, reject) => {
            const onClose = () => {
                this.connection.removeListener('error', onError); // GC
                resolve();
            }

            const onError = e => {
                this.connection.removeListener('close', onClose); // GC
                reject(e);
            }

            this.connection.once('close', onClose);
            this.connection.once('error', onError);
        });
    }

    /**
     * Write to socket connection
     * @param {number} type
     * @param {number} id
     * @param {string} body
     * @returns {Promise<DecodedPacket>}
     */
    write (type, id, body) {
        this.packetResponseCallback[ id ] = {};

        const packetIDAck = this.generatePacketID();

        if( type === Protocol.SERVERDATA_AUTH ){
            this.authRequest = id;
        }
        else{
            this.responseAck[ packetIDAck ] = {};

            this.responseAck[ packetIDAck ].id = id;
            this.responseAck[ packetIDAck ].type = type;

            this.responseExecute[ id ] = '';
        }

        return new Promise((resolve, reject) => {
            this.packetResponseCallback[ id ] = ( decodedPacket ) => {
                resolve( decodedPacket );
            }

            const encodedPacket = Packet.encode(type, id, body, this.encoding);

            if (this.maximumPacketSize > 0 && encodedPacket.length > this.maximumPacketSize){
                reject(Error('Packet too long'));
            }

            this.connection.write(encodedPacket);

            if( type !== Protocol.SERVERDATA_AUTH ){
                const encodedPacketAck = Packet.encode(Protocol.SERVERDATA_RESPONSE_VALUE, packetIDAck, '', this.encoding);
                
                this.connection.write(encodedPacketAck);
            }
        });
    }

    /**
     * Execute command to server
     * @param {string} command
     * @returns {Promise<string>} Response string
     */
    execute (command) {
        return new Promise((resolve, reject) => {
            const packetID = this.generatePacketID();

            if( !packetID ){
                return reject(Error(`Couldn't generate unique id`));
            }

            if (!this.connection.writable)
                reject(Error('Unable to write to socket'));

            if (!this.authenticated)
                reject(Error('Unable to authenticate'));

            this.write(Protocol.SERVERDATA_EXECCOMMAND, packetID, command, this.encoding)
                .then(data => resolve(data))
                .catch(reject);
        });
    }

    generatePacketID(){
        for( let currentPacketId = 1;currentPacketId <= 256; currentPacketId++ ){
            if( this.responseAck[ currentPacketId ] ){
                continue;
            }

            return currentPacketId;
        }

        return 0;
    }
}

/**
 * SourceRCON module
 * @module rcon
 */
module.exports = SourceRCON
