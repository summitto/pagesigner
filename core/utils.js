/* eslint-disable no-unused-vars */
/* eslint-disable no-undef */
/* global chrome, CBOR, COSE, Buffer, fastsha256 */

import {verifyChain} from './verifychain.js';
import * as asn1js from './third-party/pkijs/asn1.js';
import Certificate from './third-party/pkijs/Certificate.js';

// returns an array of obj's keys converted to numbers sorted ascendingly
export function sortKeys(obj){
  const numArray = Object.keys(obj).map(function(x){return Number(x);});
  return numArray.sort(function(a, b){return a-b;});
}

// convert a Uint8Array into a hex string
export function ba2hex(ba) {
  assert(ba instanceof Uint8Array);
  let hexstring = '';
  for (const b of ba) {
    let hexchar = b.toString(16);
    if (hexchar.length == 1) {
      hexchar = '0' + hexchar;
    }
    hexstring += hexchar;
  }
  return hexstring;
}

// convert a hex string into a Uint8Array
export function hex2ba(str) {
  const ba = [];
  // pad with a leading 0 if necessary
  if (str.length % 2) {
    str = '0' + str;
  }
  for (let i = 0; i < str.length; i += 2) {
    ba.push(parseInt('0x' + str.substr(i, 2)));
  }
  return new Uint8Array(ba);
}

// test a string against a string with a * wildcard
export function wildcardTest(wildStr, str) {
  var index = wildStr.indexOf('*');
  if (index > -1){
    // if wildStr has an asterisk then we match from the end up to the asterisk
    var substringAfterAsterisk = wildStr.slice(index+1);
    return str.endsWith(substringAfterAsterisk);
  }
  else{
    // if it doesnt contain an asterisk then wildStr must be equal to str
    return (wildStr == str);
  }
}

// ba2int converts a bit-endian byte array into a Number or BigInt
export function ba2int(ba){
  assert(ba instanceof Uint8Array);
  if (ba.length <= 8){
    let retval = 0;
    for (let i = 0; i < ba.length; i++) {
      retval |= ba[ba.length - 1 - i] << 8 * i;
    }
    return retval;
  }
  else {
    var hexstr = '';
    for (let byte of ba){
      let hexbyte = byte.toString(16);
      if (hexbyte.length == 1) {
        hexbyte = '0' + hexbyte;
      }
      hexstr += hexbyte;
    }
    return BigInt('0x'+hexstr);
  }
}


// int2ba converts Number or BigInt into a byte array,
// optionally padding it to the desired length
export function int2ba(int, size){
  assert(typeof(int) == 'bigint' || typeof(int) == 'number', 'Only can convert Number or BigInt');
  let hexstr = int.toString(16);
  if (hexstr.length % 2) {
    hexstr = '0' + hexstr; }
  const ba = [];
  for (let i=0; i < hexstr.length/2; i++){
    ba.push(parseInt(hexstr.slice(2*i, 2*i+2), 16));
  }
  if (size){
    const oldlen = ba.length;
    for (let j = 0; j < (size - oldlen); j++) {
      ba.unshift(0);
    }
  }
  return new Uint8Array(ba);
}


// converts string to byte array
export function str2ba(str) {
  if (typeof(str) !== 'string') {
    throw ('Only type string is allowed in str2ba');
  }
  const ba = new Uint8Array(str.length);
  for (let i = 0; i < str.length; i++) {
    ba[i] = str.charCodeAt(i);
  }
  return ba;
}

export function ba2str(ba) {
  assert(ba instanceof Uint8Array);
  let result = '';
  for (const b of ba) {
    result += String.fromCharCode(b);
  }
  return result;
}

// xor 2 byte arrays of equal length
export function xor (a, b){
  assert(a instanceof Uint8Array && b instanceof Uint8Array);
  assert(a.length == b.length);
  var c = new Uint8Array(a.length);
  for (var i=0; i< a.length; i++){
    c[i] = a[i]^b[i];
  }
  return c;
}


export async function sha256(ba) {
  assert(ba instanceof Uint8Array);
  return new Uint8Array(await crypto.subtle.digest('SHA-256', ba.buffer));
}

export function assert(condition, message) {
  if (!condition) {
    console.trace();
    throw message || 'Assertion failed';
  }
}

export function getRandom(number) {
  return crypto.getRandomValues(new Uint8Array(number));
}

// verifySig verifies a signature in p1363 format against a
// pubkey in raw format. The signature is over "signed_digest".
export async function verifySig(pubkeyRaw, sig_p1363, signed_digest){
  try {
    const pubkey = await crypto.subtle.importKey(
      'raw',
      pubkeyRaw.buffer,
      {name: 'ECDSA', namedCurve: 'P-256'},
      true,
      ['verify']);
    var result = await crypto.subtle.verify(
      {'name': 'ECDSA', 'hash': 'SHA-256'},
      pubkey,
      sig_p1363.buffer,
      signed_digest.buffer);
  } catch (e) {
    console.log(e, e.name);
    throw(e);
  }
  return result;
}

// input is Uint8Array
export async function verifyAttestationDoc(doc){
  // extract x,y from EC pubkey
  const decoded = CBOR.decode(doc.buffer);
  const payload = decoded[2].slice(); // need to copy otherwise .buffer will access ab
  const doc_obj = CBOR.decode(payload.buffer);
  const leafCertDer = doc_obj.certificate.slice();
  const cert_asn1 = asn1js.fromBER(leafCertDer.buffer);
  const leafCert = new Certificate({ schema: cert_asn1.result });
  const x = new Uint8Array(leafCert.subjectPublicKeyInfo.parsedKey.x);
  const y = new Uint8Array(leafCert.subjectPublicKeyInfo.parsedKey.y);
  // verify the signature
  COSE.verify(x, y, doc.buffer);

  // verify certificate chain

  // this is a sha256 hash of root cert from https://aws-nitro-enclaves.amazonaws.com/AWS_NitroEnclaves_Root-G1.zip
  // root.pem must be converted to der with pem2ab()
  const rootCertDer = doc_obj.cabundle[0].slice();
  const rootCertHash = '641a0321a3e244efe456463195d606317ed7cdcc3c1756e09893f3c68f79bb5b';
  assert(ba2hex(await sha256(rootCertDer)) === rootCertHash);
  const rootCert = new Certificate({ schema: asn1js.fromBER(rootCertDer.buffer).result});

  // reverse cabundle ordering
  const certChain = [leafCertDer];
  for (let i=doc_obj.cabundle.length-1; i >=0; i--){
    certChain.push(doc_obj.cabundle[i].slice());
  }
  // verifying against the time when the attestation doc was retrieved
  var vcrv = await verifyChain(certChain, leafCert.notBefore.value, [rootCert]);
  assert (vcrv.result == true);
  console.log('cert chain verification successful');

  // return user_data and PCRs
  return [doc_obj.user_data, doc_obj.pcrs[0], doc_obj.pcrs[1], doc_obj.pcrs[2]];
}


export function b64encode(ba) {
  assert(ba instanceof Uint8Array);
  if (typeof(window) === 'undefined') {
    // running in nodejs
    return Buffer.from(ba).toString('base64');
  }
  else {
    // if aBytes is too large > ~100 KB, we may get an error
    // RangeError: Maximum call stack size exceeded
    // therefore we split the input into chunks
    var strings = '';
    var chunksize = 4096;
    for (var i = 0; i * chunksize < ba.length; i++){
      strings += String.fromCharCode.apply(null, ba.slice(i * chunksize, (i + 1) * chunksize));
    }
    return btoa(strings);
  }
}


export function b64decode(str) {
  let dec;
  if (typeof(window) === 'undefined') {
    // running in nodejs
    dec = Buffer.from(str, 'base64');
  }
  else {
    dec = atob(str).split('').map(function(c) {
      return c.charCodeAt(0);
    });
  }
  return new Uint8Array(dec);
}

// conform to base64url format replace +/= with -_
export function b64urlencode (ba){
  assert(ba instanceof Uint8Array);
  let str = b64encode(ba);
  return str.split('+').join('-').split('/').join('_').split('=').join('');
}


export function buildChunkMetadata(plaintextArr){
  let http_data = '';
  for (const pt of plaintextArr){
    http_data += ba2str(pt);
  }

  const chunkMetadata = [];
  // '''Dechunk only if http_data is chunked otherwise return http_data unmodified'''
  const http_header = http_data.slice(0, http_data.search('\r\n\r\n') + '\r\n\r\n'.length);
  // #\s* below means any amount of whitespaces
  if (http_header.search(/transfer-encoding:\s*chunked/i) === -1) {
    return []; // #nothing to dechunk
  }

  // all offsets are relative to the beginning of the HTTP response
  let cur_offset = http_header.length;
  let chunk_len = -1; // #initialize with a non-zero value
  while (true) {
    var new_offset = http_data.slice(cur_offset).search('\r\n');
    if (new_offset === -1) { // #pre-caution against endless looping
      // #pinterest.com is known to not send the last 0 chunk when HTTP gzip is disabled
      break;
    }
    var chunk_len_hex = http_data.slice(cur_offset, cur_offset + new_offset);
    chunk_len = parseInt(chunk_len_hex, 16);
    if (chunk_len === 0) {
      chunkMetadata.push(cur_offset-2);
      chunkMetadata.push(cur_offset+ '0\r\n\r\n'.length - 1);
      break; // #for properly-formed ml we should break here
    }
    if (cur_offset == http_header.length){
      chunkMetadata.push(http_header.length);
    }
    else {
      chunkMetadata.push(cur_offset-2);
    }
    cur_offset += new_offset + '\r\n'.length;
    chunkMetadata.push(cur_offset-1);
    cur_offset += chunk_len + '\r\n'.length;
  }
  return chunkMetadata;
}


// HTTP chunking metadata may be present in records. Strip the records of it.
// return the array of records with dechunked info removed
export function dechunk_http(decrRecords) {
  var http_data = '';
  for (const ct of decrRecords){
    http_data += ba2str(ct);
  }

  // '''Dechunk only if http_data is chunked otherwise return http_data unmodified'''
  const http_header = http_data.slice(0, http_data.search('\r\n\r\n') + '\r\n\r\n'.length);
  // #\s* below means any amount of whitespaces
  var stopat = 0;
  if (http_header.search(/transfer-encoding:\s*chunked/i) === -1) {
    return decrRecords; // #nothing to dechunk
  }

  var chunkMetadata = buildChunkMetadata(decrRecords);
  var dechunkedPlaintexts = [];
  var totalOffset = -1; // an offset at which the last byte is found of plaintexts processed so far
  var shrinkNextRecordBy = 0; // used when chunking metadata spans 2 TLS records
  var shrinkThisRecordBy = 0;
  for (var i=0; i < decrRecords.length; i++){
    shrinkThisRecordBy = shrinkNextRecordBy;
    shrinkNextRecordBy = 0;
    var ct = decrRecords[i];
    totalOffset += ct.length;
    if (stopat){
      if (stopat < [].concat.apply([], dechunkedPlaintexts).length - 500){
        var s = true;
      }
    }
    var metadataInThisRecord = [];
    var tmpArray = [...chunkMetadata];
    // every even index contains the start of metadata
    for (var j=0; j < tmpArray.length; j+=2){
      if (tmpArray[j] > totalOffset) break;
      // else
      if (tmpArray[j+1] > totalOffset){
        // chunking metadata spans 2 TLS records
        if (shrinkNextRecordBy) {
          // already was spanning 2 TLS records
          throw('chunking metadata spans 3 TLS records. Please report to the developers for investigation');
        }
        shrinkNextRecordBy = tmpArray[j+1] - totalOffset;
      }
      metadataInThisRecord.push(tmpArray[j]- (totalOffset+1 - ct.length));
      metadataInThisRecord.push(tmpArray[j+1] - (totalOffset+1 - ct.length));
      chunkMetadata.shift();
      chunkMetadata.shift();
    }

    const dechunkedRecord = [];
    // if we need to shrink the record but the record itself consists only of partial metadata
    // and its size is less than the amount we need to shrink
    if (shrinkThisRecordBy && (ct.length < shrinkThisRecordBy)){
      assert(shrinkNextRecordBy == 0);
      shrinkNextRecordBy = shrinkThisRecordBy - ct.length;
      dechunkedPlaintexts.push([]);
      continue;
    }

    var fromPos = shrinkThisRecordBy; // set to 0 when metadata doesnt span 2 records
    for (var k=0; k < metadataInThisRecord.length; k+=2){
      // offsets in metadataInThisRecord relative to this record
      if (k+2 == metadataInThisRecord.length && i+1 == decrRecords.length){
        // set breakpoint here
        var s = true;
      }
      var startOffset = metadataInThisRecord[k];
      var slice = ct.slice(fromPos, startOffset);
      dechunkedRecord.push(slice);
      fromPos = metadataInThisRecord[k+1]+1;
    }
    var lastSlice = ct.slice(fromPos);
    dechunkedRecord.push(lastSlice);
    dechunkedPlaintexts.push(concatTA(...dechunkedRecord));
  }
  return dechunkedPlaintexts;
}




export function gunzip_http(dechunkedRecords) {
  var http_data = '';
  for (let rec of dechunkedRecords){
    http_data += rec;
  }

  var http_header = http_data.slice(0, http_data.search('\r\n\r\n') + '\r\n\r\n'.length);
  // #\s* below means any amount of whitespaces
  if (http_header.search(/content-encoding:\s*deflate/i) > -1) {
    // #TODO manually resend the request with compression disabled
    throw ('please disable compression and rerun the notarization');
  }
  if (http_header.search(/content-encoding:\s.*gzip/i) === -1) {
    console.log('nothing to gunzip');
    return dechunkedRecords; // #nothing to gunzip
  }
  throw ('gzip enabled');
  // var http_body = http_data.slice(http_header.length);
  // var ungzipped = http_header;
  // if (!http_body) {
  //   // HTTP 304 Not Modified has no body
  //   return [ungzipped];
  // }
  // var inflated = pako.inflate(http_body);
  // ungzipped += ba2str(inflated);
  // return [ungzipped];
}

export function getTime() {
  var today = new Date();
  var time = today.getFullYear() + '-' +
    ('00' + (today.getMonth() + 1)).slice(-2) + '-' +
    ('00' + today.getDate()).slice(-2) + '-' +
    ('00' + today.getHours()).slice(-2) + '-' +
    ('00' + today.getMinutes()).slice(-2) + '-' +
    ('00' + today.getSeconds()).slice(-2);
  return time;
}

// PEM certificate/pubkey to byte array
export function pem2ba(pem) {
  var lines = pem.split('\n');
  var encoded = '';
  for(let line of lines){
    if (line.trim().length > 0 &&
        line.indexOf('-BEGIN CERTIFICATE-') < 0 &&
        line.indexOf('-BEGIN PUBLIC KEY-') < 0 &&
        line.indexOf('-END PUBLIC KEY-') < 0 &&
        line.indexOf('-END CERTIFICATE-') < 0 ) {
      encoded += line.trim();
    }
  }
  return b64decode(encoded);
}


// compares two Uint8Arrays or Arrays
export function eq(a, b) {
  assert(Array.isArray(a) || a instanceof Uint8Array);
  assert(Array.isArray(b) || b instanceof Uint8Array);
  return a.length === b.length &&
    a.every((val, index) => val === b[index]);
}


// expand the range [min:max) into array of ints 1,2,3,4... up to but not including max
export function expandRange(min, max){
  const arr = [];
  for (let i=0; i < max-min; i++){
    arr.push(min + i);
  }
  return arr;
}


// split Array or Uint8Array into an array of chunks
export function splitIntoChunks(ba, chunkSize) {
  assert(ba instanceof Uint8Array);
  assert(ba.length % chunkSize === 0);
  const newArray = [];
  const chunkCount = ba.length / chunkSize;
  for (let i=0; i < chunkCount; i++){
    newArray.push(ba.slice(i*chunkSize, (i+1)*chunkSize));
  }
  return newArray;
}


// convert Uint8Array into an array of 0/1 where least bit has index 0
export function bytesToBits (ba){
  assert(ba instanceof Uint8Array);
  const bitArr = Array(ba.length*8);
  let idx = 0;
  for (let i=ba.length-1; i >= 0; i--){
    for (let j=0; j < 8; j++){
      bitArr[idx] = (ba[i] >> j) & 0x01;
      idx++;
    }
  }
  return bitArr;
}

// convert an array of 0/1 (with least bit at index 0) to Uint8Array
export function bitsToBytes(arr){
  assert(arr.length % 8 === 0);
  const ba = new Uint8Array(arr.length/8);
  for (let i=0; i < ba.length; i++){
    let sum = 0;
    for (let j=0; j < 8; j++){
      sum += arr[i*8+j] * (2**j);
    }
    ba[ba.length-1-i] = sum;
  }
  return ba;
}


// convert OpenSSL's signature format (asn1 DER) into WebCrypto's IEEE P1363 format
export function sigDER2p1363(sigDER){
  var o = 0;
  assert(eq(sigDER.slice(o, o+=1), [0x30]));
  var total_len = ba2int(sigDER.slice(o, o+=1));
  assert(sigDER.length == total_len+2);
  assert(eq(sigDER.slice(o, o+=1), [0x02]));
  var r_len = ba2int(sigDER.slice(o, o+=1));
  assert(r_len === 32 || r_len === 33);
  var r = sigDER.slice(o, o+=r_len);
  assert(eq(sigDER.slice(o, o+=1), [0x02]));
  var s_len = ba2int(sigDER.slice(o, o+=1));
  assert(s_len >= 31 && s_len <= 33);
  var s = sigDER.slice(o, o+=s_len);
  if (s.length === 31){
    s = concatTA(new Uint8Array([0x00]), s);
  }
  if (r_len === 33){
    assert(eq(r.slice(0, 1), [0x00]));
    r = r.slice(1);
  }
  if (s_len == 33){
    assert(eq(s.slice(0, 1), [0x00]));
    s = s.slice(1);
  }
  var sig_p1363 = concatTA(r, s);
  return sig_p1363;
}


// we can import chrome:// and file:// URL
export async function import_resource(filename) {
  var path = chrome.extension.getURL(filename);
  var resp = await fetch(path);
  var data = await resp.text();
  return data;
}

// take PEM EC pubkey and output a "raw" pubkey with all asn1 data stripped
export function pubkeyPEM2raw(pkPEM){
  // prepended asn1 data for ECpubkey prime256v1
  const preasn1 = [0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00];
  const pk = pem2ba(pkPEM);
  assert(eq(pk.slice(0, preasn1.length), preasn1));
  return pk.slice(preasn1.length);
}

// states are Int32Array just lke fastsha expects
// msg and output are byte arrays
export function finishHMAC(innerState, outerState, msg) {
  const ihasher = new fastsha256.Hash();
  const ohasher = new fastsha256.Hash();
  ihasher._restoreState(innerState, 64);
  ihasher.update(msg);
  const iHash = ihasher.digest();
  ohasher._restoreState(outerState, 64);
  ohasher.update(iHash);
  return ohasher.digest();
}

// state is Int32Array just lke fastsha expects
// msg and output are byte arrays
export function innerHash(innerState, msg) {
  assert (innerState instanceof Int32Array);
  assert (msg instanceof Uint8Array);

  const ihasher = new fastsha256.Hash();
  ihasher._restoreState(innerState, 64);
  ihasher.update(msg);
  return ihasher.digest();
}

export async function wait(timeout) {
  return await new Promise((resolve) => {
    setTimeout(function(){
      resolve('wait');
    }, timeout);
  });
}

export const fetchTimeout = (url, ms, { signal, ...options } = {}) => {
  const controller = new AbortController();
  const promise = fetch(url, { signal: controller.signal, ...options });
  if (signal) signal.addEventListener('abort', () => controller.abort());
  const timeout = setTimeout(() => controller.abort(), ms);
  return promise.finally(() => clearTimeout(timeout));
};

// concatTA concatenates typed arrays of type Uint8Array
export function concatTA(...arr){
  let newLen = 0;
  for (const item of arr){
    assert(item instanceof Uint8Array);
    newLen += item.length;
  }
  const newArray = new Uint8Array(newLen);
  let offset = 0;
  for (const item of arr){
    newArray.set(item, offset);
    offset += item.length;
  }
  return newArray;
}

// WebCrypto doesn't provide AES-ECB encryption. We achieve it by using
// the CBC mode with a zero IV. This workaraound only works for encrypting
// 16 bytes at a time.

export async function AESECBencrypt(key, data){
  assert(data.length == 16, 'can only AES-ECB encrypt 16 bytes at a time');
  const cryptoKey = await crypto.subtle.importKey(
    'raw', key.buffer, 'AES-CBC', false, ['encrypt']);

  // Even if data is a multiple of 16, WebCrypto adds 16 bytes of
  // padding. We drop it.
  return new Uint8Array (await crypto.subtle.encrypt({
    name: 'AES-CBC',
    iv: new Uint8Array(16).fill(0).buffer},
  cryptoKey,
  data.buffer)).slice(0, 16);
}

// use Salsa20 as a random permutator. Instead of the nonce, we feed the data that needs
// to be permuted.
export function Salsa20(key, data){
  // sigma is Salsa's constant "expand 32-byte k"
  const sigma = new Uint8Array([101, 120, 112, 97, 110, 100, 32, 51, 50, 45, 98, 121, 116, 101, 32, 107]);
  const out = new Uint8Array(16);
  core_salsa20(out, data, key, sigma);
  return out;
}

// copied from https://github.com/dchest/tweetnacl-js/blob/master/nacl-fast.js
// and modified to output only 16 bytes
function core_salsa20(o, p, k, c) {
  var j0  = c[ 0] & 0xff | (c[ 1] & 0xff)<<8 | (c[ 2] & 0xff)<<16 | (c[ 3] & 0xff)<<24,
    j1  = k[ 0] & 0xff | (k[ 1] & 0xff)<<8 | (k[ 2] & 0xff)<<16 | (k[ 3] & 0xff)<<24,
    j2  = k[ 4] & 0xff | (k[ 5] & 0xff)<<8 | (k[ 6] & 0xff)<<16 | (k[ 7] & 0xff)<<24,
    j3  = k[ 8] & 0xff | (k[ 9] & 0xff)<<8 | (k[10] & 0xff)<<16 | (k[11] & 0xff)<<24,
    j4  = k[12] & 0xff | (k[13] & 0xff)<<8 | (k[14] & 0xff)<<16 | (k[15] & 0xff)<<24,
    j5  = c[ 4] & 0xff | (c[ 5] & 0xff)<<8 | (c[ 6] & 0xff)<<16 | (c[ 7] & 0xff)<<24,
    j6  = p[ 0] & 0xff | (p[ 1] & 0xff)<<8 | (p[ 2] & 0xff)<<16 | (p[ 3] & 0xff)<<24,
    j7  = p[ 4] & 0xff | (p[ 5] & 0xff)<<8 | (p[ 6] & 0xff)<<16 | (p[ 7] & 0xff)<<24,
    j8  = p[ 8] & 0xff | (p[ 9] & 0xff)<<8 | (p[10] & 0xff)<<16 | (p[11] & 0xff)<<24,
    j9  = p[12] & 0xff | (p[13] & 0xff)<<8 | (p[14] & 0xff)<<16 | (p[15] & 0xff)<<24,
    j10 = c[ 8] & 0xff | (c[ 9] & 0xff)<<8 | (c[10] & 0xff)<<16 | (c[11] & 0xff)<<24,
    j11 = k[16] & 0xff | (k[17] & 0xff)<<8 | (k[18] & 0xff)<<16 | (k[19] & 0xff)<<24,
    j12 = k[20] & 0xff | (k[21] & 0xff)<<8 | (k[22] & 0xff)<<16 | (k[23] & 0xff)<<24,
    j13 = k[24] & 0xff | (k[25] & 0xff)<<8 | (k[26] & 0xff)<<16 | (k[27] & 0xff)<<24,
    j14 = k[28] & 0xff | (k[29] & 0xff)<<8 | (k[30] & 0xff)<<16 | (k[31] & 0xff)<<24,
    j15 = c[12] & 0xff | (c[13] & 0xff)<<8 | (c[14] & 0xff)<<16 | (c[15] & 0xff)<<24;

  var x0 = j0, x1 = j1, x2 = j2, x3 = j3, x4 = j4, x5 = j5, x6 = j6, x7 = j7,
    x8 = j8, x9 = j9, x10 = j10, x11 = j11, x12 = j12, x13 = j13, x14 = j14,
    x15 = j15, u;

  for (var i = 0; i < 20; i += 2) {
    u = x0 + x12 | 0;
    x4 ^= u<<7 | u>>>(32-7);
    u = x4 + x0 | 0;
    x8 ^= u<<9 | u>>>(32-9);
    u = x8 + x4 | 0;
    x12 ^= u<<13 | u>>>(32-13);
    u = x12 + x8 | 0;
    x0 ^= u<<18 | u>>>(32-18);

    u = x5 + x1 | 0;
    x9 ^= u<<7 | u>>>(32-7);
    u = x9 + x5 | 0;
    x13 ^= u<<9 | u>>>(32-9);
    u = x13 + x9 | 0;
    x1 ^= u<<13 | u>>>(32-13);
    u = x1 + x13 | 0;
    x5 ^= u<<18 | u>>>(32-18);

    u = x10 + x6 | 0;
    x14 ^= u<<7 | u>>>(32-7);
    u = x14 + x10 | 0;
    x2 ^= u<<9 | u>>>(32-9);
    u = x2 + x14 | 0;
    x6 ^= u<<13 | u>>>(32-13);
    u = x6 + x2 | 0;
    x10 ^= u<<18 | u>>>(32-18);

    u = x15 + x11 | 0;
    x3 ^= u<<7 | u>>>(32-7);
    u = x3 + x15 | 0;
    x7 ^= u<<9 | u>>>(32-9);
    u = x7 + x3 | 0;
    x11 ^= u<<13 | u>>>(32-13);
    u = x11 + x7 | 0;
    x15 ^= u<<18 | u>>>(32-18);

    u = x0 + x3 | 0;
    x1 ^= u<<7 | u>>>(32-7);
    u = x1 + x0 | 0;
    x2 ^= u<<9 | u>>>(32-9);
    u = x2 + x1 | 0;
    x3 ^= u<<13 | u>>>(32-13);
    u = x3 + x2 | 0;
    x0 ^= u<<18 | u>>>(32-18);

    u = x5 + x4 | 0;
    x6 ^= u<<7 | u>>>(32-7);
    u = x6 + x5 | 0;
    x7 ^= u<<9 | u>>>(32-9);
    u = x7 + x6 | 0;
    x4 ^= u<<13 | u>>>(32-13);
    u = x4 + x7 | 0;
    x5 ^= u<<18 | u>>>(32-18);

    u = x10 + x9 | 0;
    x11 ^= u<<7 | u>>>(32-7);
    u = x11 + x10 | 0;
    x8 ^= u<<9 | u>>>(32-9);
    u = x8 + x11 | 0;
    x9 ^= u<<13 | u>>>(32-13);
    u = x9 + x8 | 0;
    x10 ^= u<<18 | u>>>(32-18);

    u = x15 + x14 | 0;
    x12 ^= u<<7 | u>>>(32-7);
    u = x12 + x15 | 0;
    x13 ^= u<<9 | u>>>(32-9);
    u = x13 + x12 | 0;
    x14 ^= u<<13 | u>>>(32-13);
    u = x14 + x13 | 0;
    x15 ^= u<<18 | u>>>(32-18);
  }
  x0 =  x0 +  j0 | 0;
  x1 =  x1 +  j1 | 0;
  x2 =  x2 +  j2 | 0;
  x3 =  x3 +  j3 | 0;
  x4 =  x4 +  j4 | 0;
  x5 =  x5 +  j5 | 0;
  x6 =  x6 +  j6 | 0;
  x7 =  x7 +  j7 | 0;
  x8 =  x8 +  j8 | 0;
  x9 =  x9 +  j9 | 0;
  x10 = x10 + j10 | 0;
  x11 = x11 + j11 | 0;
  x12 = x12 + j12 | 0;
  x13 = x13 + j13 | 0;
  x14 = x14 + j14 | 0;
  x15 = x15 + j15 | 0;

  o[ 0] = x0 >>>  0 & 0xff;
  o[ 1] = x0 >>>  8 & 0xff;
  o[ 2] = x0 >>> 16 & 0xff;
  o[ 3] = x0 >>> 24 & 0xff;

  o[ 4] = x1 >>>  0 & 0xff;
  o[ 5] = x1 >>>  8 & 0xff;
  o[ 6] = x1 >>> 16 & 0xff;
  o[ 7] = x1 >>> 24 & 0xff;

  o[ 8] = x2 >>>  0 & 0xff;
  o[ 9] = x2 >>>  8 & 0xff;
  o[10] = x2 >>> 16 & 0xff;
  o[11] = x2 >>> 24 & 0xff;

  o[12] = x3 >>>  0 & 0xff;
  o[13] = x3 >>>  8 & 0xff;
  o[14] = x3 >>> 16 & 0xff;
  o[15] = x3 >>> 24 & 0xff;
  // we only need 16 bytes of the output
}


// ephemeral key usage time must be within the time of ephemeral key validity
export function checkExpiration(validFrom, validUntil, time){
  time = time || Math.floor(new Date().getTime() / 1000);
  if (ba2int(validFrom) > time || time > ba2int(validUntil)){
    return false;
  }
  return true;
}
