import { Point, Signature, SECP256R1 } from '../../scrypt-ts-lib'
import { method, assert, SmartContract } from 'scrypt-ts'

export class VerifyOnly extends SmartContract {
    @method()
    public verifySig(data: bigint, sig: Signature, pubKey: Point) {
        assert(SECP256R1.verifySig(data, sig, pubKey))
    }
}
