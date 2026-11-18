const fs = require('node:fs')
const crypto = require('node:crypto')
const path = require('node:path')
const { buildContractClass } = require(path.join(process.cwd(), 'node_modules/scryptlib'))
const artifact = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'))
const only = process.env.CASE === 'verifyOnly'
if (artifact.contract !== (only ? 'VerifyOnly' : 'SECP256R1Test')) throw new Error('unexpected artifact')
const v = JSON.parse(fs.readFileSync(process.argv[3], 'utf8'))
const instance = new (buildContractClass(artifact))()
const integer = x => BigInt('0x' + x)
const sig = { r: integer(v.signature_hex.slice(0, 64)), s: integer(v.signature_hex.slice(64)) }
const q = v.public_key_x963
const pub = { x: integer(q.slice(2, 66)), y: integer(q.slice(66)) }
const inputs = [integer(v.digest_hex), sig, pub]
const call = only ? instance.verifySig(...inputs) : instance.verifySig(...inputs, true)
const out = process.env.RUNNER_TEMP
function save(name, hex) {
  const bytes = Buffer.from(hex, 'hex')
  if (hex.length !== 2 * bytes.length) throw new Error('invalid script encoding')
  fs.writeFileSync(path.join(out, name + '.bin'), bytes)
  return {bytes: bytes.length, sha256: crypto.createHash('sha256').update(bytes).digest('hex')}
}
console.log('RESULT', JSON.stringify({
  contract: artifact.contract, compiler: artifact.compilerVersion, abi: artifact.abi.map(m => m.name),
  scryptLock: save('scrypt-lock', instance.lockingScript.toHex()),
  scryptUnlock: save('scrypt-unlock', call.toScript().toHex()),
  pelsLock: save('pels-lock', fs.readFileSync(path.join(path.dirname(process.argv[3]), 'template.hex'), 'utf8').replace(/\s/g,'')),
  pelsUnlock: save('pels-unlock', v.script_sig_hex)
}))
