/*!
 * Doublespeak JavaScript Library
 *
 * Copyright (c) 2017 Joshua Fan <joshuaptfan@gmail.com>
 * MIT License
 *
 * https://github.com/dblspk/lib
 */
function Doublespeak(isDebug = false) {
	this.encVals = Object.freeze({
		'\u200C': 0x0, // zero-width non-joiner
		'\u200D': 0x1, // zero-width joiner
		'\u2060': 0x2, // word joiner
		'\u2061': 0x3, // function application
		'\u2062': 0x4, // invisible times
		'\u2063': 0x5, // invisible separator
		'\u2064': 0x6, // invisible plus
		'\u206A': 0x7, // inhibit symmetric swapping
		'\u206B': 0x8, // activate symmetric swapping
		'\u206C': 0x9, // inhibit Arabic form shaping
		'\u206D': 0xA, // activate Arabic form shaping
		'\u206E': 0xB, // national digit shapes
		'\u206F': 0xC, // nominal digit shapes
		'\uFE00': 0xD, // variation selector-1
		'\uFE01': 0xE, // variation selector-2
		'\uFEFF': 0xF  // zero-width non-breaking space
	});
	this.encChars = Object.freeze(Object.keys(this.encVals));

	/**
	 * Encode integer as variable length quantity in byte array.
	 * @param {Number} n
	 * @return {Uint8Array}
	 */
	this.encodeLength = function (n) {
		let bytes = [n & 0x7F];
		while (n > 127) {
			n >>= 7;
			bytes.unshift(n & 0x7F | 0x80);
		}

		return Uint8Array.from(bytes);
	};

	/**
	 * Decode variable length quantity to integer.
	 * @param {Uint8Array} bytes
	 * @return {Number}
	 */
	this.decodeLength = function (bytes) {
		let len = 0;
		for (var i = 0; i < bytes.length; i++)
			len = len << 7 | bytes[i] & 0x7F;

		return len;
	};

	/**
	 * Convert byte arrays to encoding characters.
	 * @param {...(Uint8Array|Number[])} args
	 * @return {String}
	 */
	this.encodeBytes = function (...args) {
		const encChars = this.encChars;

		let out = '';
		for (var arg of args) {
			if (!arg) continue;
			if (!(arg instanceof Uint8Array))
				arg = Uint8Array.from(arg);
			for (var i = 0, aLen = arg.length; i < aLen; i++)
				out += encChars[arg[i] >> 4] + encChars[arg[i] & 0xF];
		}

		return out;
	};

	/**
	 * Convert encoded messages in string to byte array.
	 * @param {String} str
	 * @return {Object}
	 */
	this.decodeBytes = function (str) {
		const encVals = this.encVals;

		// Collect encoding characters and translate to half-bytes
		let cover = '';
		let nybles = [];
		let seqLens = [];
		for (var i = 0, sLen = str.length; i < sLen;) {
			var val = encVals[str[i]];
			if (val === undefined)
				cover += str[i++];
			else {
				let seq = [];
				do {
					seq.push(val);
					val = encVals[str[++i]];
				} while (val !== undefined);
				// Ignore short sequences of encoding characters
				if (seq.length < 16)
					cover += seq;
				else {
					// If sequence is truncated by an odd number of half-bytes,
					// drop last half-byte to preserve byte alignment
					if (seq.length & 1) seq.pop();
					nybles = nybles.concat(seq);
					seqLens.push(seq.length >> 1);
				}
			}
		}

		// Convert half-bytes to bytes
		let bytes = [];
		for (var i = 0, nLen = nybles.length; i < nLen; i += 2)
			bytes.push(nybles[i] << 4 | nybles[i + 1]);

		return { cover, bytes: Uint8Array.from(bytes), seqLens };
	};

	/**
	 * Remove encoded messages from string.
	 * @param {String} str
	 * @return {String}
	 */
	this.filterStr = function (str) {
		const encVals = this.encVals;

		let out = '';
		for (var i = 0, sLen = str.length; i < sLen;) {
			if (encVals[str[i]] === undefined)
				out += str[i++];
			else {
				let seq = str[i];
				while (encVals[str[++i]] !== undefined)
					seq += str[i];
				if (seq.length < 16)
					out += seq;
			}
		}

		return out;
	};

	/**
	 * Encode plaintext to ciphertext.
	 * @param {String} str
	 * @return {Promise}
	 */
	this.encodeText = function (str) {
		const bytes = new TextEncoder().encode(this.filterStr(str));
		const salt = crypto.getRandomValues(new Uint8Array(16));

		let encode = (bytes, salt) => {
			// 0x44 0x0 == 'D\u0000' protocol signature and version
			const str = bytes.length ? this.encodeBytes([0x44, 0x0], this.crc32(bytes).bytes, [!this.masterKey ? 0x1 : 0x0], this.encodeLength(bytes.length), salt && [0x0], salt, bytes) : '';
			if (isDebug) console.info('Original size:', bytes.length, 'bytes',
				'\nEncoded size:', str.length * 3, 'bytes,', str.length, 'characters');
			return str;
		};

		return !this.masterKey
			? Promise.resolve(encode(bytes))
			: this.encrypt(bytes, salt, encode);
	};

	/**
	 * Encode file info and file byte array to ciphertext.
	 * @param {String} type
	 * @param {String} name
	 * @param {Uint8Array} bytes
	 * @return {Promise}
	 */
	this.encodeFile = function (type, name, bytes) {
		const head = new TextEncoder().encode(type + '\0' + name + '\0');
		let pack = new Uint8Array(head.length + bytes.length);
		pack.set(head);
		pack.set(bytes, head.length);

		let encode = pack => {
			// 0x44 0x0 == 'D\u0000' protocol signature and version
			const str = this.encodeBytes([0x44, 0x0], this.crc32(pack).bytes, [!this.key ? 0x2 : 0x0], this.encodeLength(pack.length), pack);
			if (isDebug) console.info('File:', name + ',', (type || 'unknown'),
				'\nOriginal size:', bytes.length, 'bytes',
				'\nEncoded size:', str.length * 3, 'bytes,', str.length, ' characters');
			return str;
		};

		return !this.masterKey
			? Promise.resolve(encode(pack))
			: this.encrypt(pack, encode);
	};

	/**
	 * Decode encoded messages in string to array of data objects.
	 * @param {String} str
	 * @return {Object}
	 */
	this.decodeData = function (str) {
		let { cover, bytes, seqLens } = this.decodeBytes(str);
		let dataObjs = [];
		// Loop until all messages extracted
		do {
			// Check protocol signature and version
			if (!bytes.length || bytes[0] != 0x44 || bytes[1] != 0x0) {
				if (!bytes.length)
					dataObjs.push({ error: 'No message detected' });
				else {
					dataObjs.push({
						error: 'Protocol mismatch',
						details: '\nData: ' + new TextDecoder().decode(bytes.subarray(seqLens[0]))
					});
					bytes = bytes.subarray(seqLens.shift());
					continue;
				}
				break;
			}

			// Get length of variable length quantity data length field
			// by checking the first bit of each byte from VLQ start position
			let VLQLen = 0;
			while (bytes[6 + ++VLQLen] & 0x80) {}
			// Get start position of data field
			const dataStart = 7 + VLQLen;
			const header = bytes.subarray(2, dataStart);
			// Get data type field
			const dataType = header[4];
			// Get end position of data field
			const dataEnd = dataStart + this.decodeLength(header.subarray(5));
			// Get data field
			const data = bytes.subarray(dataStart, dataEnd);
			if (isDebug) console.info('Original size:', data.length, 'bytes',
				'\nEncoded size:', dataEnd * 6, 'bytes,', dataEnd * 2, 'characters');
			// Check CRC-32
			const crc32 = this.crc32(data);
			const crcMatch = crc32.bytes.every((v, i) => v === header[i]);

			dataObjs.push({ crcMatch, crc: crc32.crc, dataType, data });

			if (crcMatch) {
				if (dataEnd < seqLens[0])
					// Update sequence length for concatenated messages
					seqLens[0] -= dataEnd;
				else
					// Discard sequence length if no concatenation
					seqLens.shift();
			}
			// If CRC mismatch, discard current sequence
			bytes = bytes.subarray(crcMatch ? dataEnd : seqLens.shift());
		} while (bytes.length);

		return { cover, dataObjs };
	};

	/**
	 * Convert byte array to UTF-8 text.
	 * @param {Uint8Array} bytes
	 * @return {Promise}
	 */
	this.extractText = function (bytes) {
		let decode = bytes => new TextDecoder().decode(bytes);
		return this.decrypt(bytes, decode);
	};

	/**
	 * Convert byte array to file components.
	 * @param {Uint8Array} bytes
	 * @return {Promise}
	 */
	this.extractFile = function (bytes) {
		let decode = bytes => {
			// Slice byte array by null terminators
			let nullPos = [];
			for (var i = 0, bLen = bytes.length; i < bLen; i++)
				if (!bytes[i]) {
					nullPos.push(i);
					if (nullPos.length > 1) break;
				}

			const type = new TextDecoder().decode(bytes.subarray(0, nullPos[0]));
			const name = new TextDecoder().decode(bytes.subarray(nullPos[0] + 1, nullPos[1]));
			const blob = new Blob([bytes.subarray(nullPos[1] + 1)], { type });
			const url = URL.createObjectURL(blob);
			const size = blob.size;

			return { type, name, url, size };
		};

		return this.decrypt(bytes, decode);
	};

	/**
	 * Initialize CRC-32 table.
	 * @return {Number[]}
	 */
	this.crcTable = Object.freeze((() => {
		let crcTable = [];
		let c;
		for (var n = 0; n < 256; n++) {
			c = n;
			for (var i = 0; i < 8; i++)
				c = ((c & 1) ? (0xEDB88320 ^ (c >>> 1)) : (c >>> 1));
			crcTable[n] = c;
		}
		return crcTable;
	})());

	/**
	 * Calculate CRC-32 and convert to byte array.
	 * @param {Uint8Array} bytes
	 * @return {Object}
	 */
	this.crc32 = function (bytes) {
		const crcTable = this.crcTable;

		let crc = -1;
		for (var i = 0, bLen = bytes.length; i < bLen; i++)
			crc = (crc >>> 8) ^ crcTable[(crc ^ bytes[i]) & 0xFF];
		crc = (crc ^ -1) >>> 0;
		if (isDebug) console.info('CRC-32: 0x' + ('0000000' + crc.toString(16)).slice(-8));

		bytes = [];
		for (i = 24; i >= 0; i -= 8)
			bytes.push(crc >> i & 0xFF);
		return { crc, bytes: Uint8Array.from(bytes) };
	};

	/**
	 * Derive 128-bit AES-CTR encryption key from passphrase using PBKDF2.
	 * @param {String} pass
	 * @param {String} salt
	 * @return {Promise}
	 */
	this.deriveKey = function (pass) {
		if (!pass)
			this.key = null;
		else
			crypto.subtle.importKey(
				'raw',
				new TextEncoder().encode(pass),
				'PBKDF2',
				false,
				['deriveKey']
			)
			.then(masterKey => { this.masterKey = masterKey; });
	};

	/**
	 * Encrypt byte array if encryption key exists.
	 * @param {Uint8Array} bytes
	 * @param {Function} encode
	 * @return {Promise}
	 */
	this.encrypt = function (bytes, salt, encode) {
		return Promise.resolve(
			crypto.subtle.deriveKey(
				{
					name: 'PBKDF2',
					salt,
					iterations: 100,
					hash: 'SHA-256'
				},
				this.masterKey,
				{ name: 'AES-GCM', length: 128 },
				false,
				['encrypt', 'decrypt']
			)
			.then(key => {
				crypto.subtle.encrypt({
					name: 'AES-GCM',
					iv: Uint8Array.of(0)
				},
					key,
					bytes
				)
				.then(cipher => encode(new Uint8Array(cipher), salt))
			})
		);
	};

	/**
	 * Decrypt byte array if encryption key exists.
	 * @param {Uint8Array} bytes
	 * @param {Function} decode
	 * @return {Promise}
	 */
	this.decrypt = function (bytes, decode) {
		return Promise.resolve(
			!this.key
				? decode(bytes)
				: crypto.subtle.decrypt({
					name: 'AES-GCM',
					iv: ArrayBuffer(12)
				},
					this.key,
					bytes
				)
				.then(plain => decode(new Uint8Array(plain)))
		);
	};
}

module.exports = new Doublespeak();
