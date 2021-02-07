import binascii
from collections import defaultdict
from hashlib import sha256
from typing import Dict

from buidl.helper import decode_base58
from buidl.psbt import PSBTIn, PSBTOut
from buidl.script import P2WSHScriptPubKey

from hermit.errors import InvalidSignatureRequest
from hermit.signer.base import Signer, print_formatted_text, HTML


def generate_multisig_address(witnessscript: str, testnet: bool = False) -> str:
    """
    Generates a P2WSH-multisig Bitcoin address from a witness script

    Args:
        witnessscript: hex-encoded witness script
                      use generate_multisig_witness_script to create
                      the witness script from three compressed public keys
         testnet: Should the address be testnet or mainnet?

    Example:
        TODO
    """

    h160 = bytes.fromhex(witnessscript)

    return P2WSHScriptPubKey(h160).address(testnet=testnet)


class BitcoinSigner(Signer):
    """Signs BTC transactions

    Signature requests must match the following schema:

        {

          "inputs": [
            [
              WITNESS_SCRIPT,
              BIP32_PATH,
              {
                "txid": TXID,
                "index": INDEX,
                "amount": SATOSHIS
              },
              ...
            ],
            ...
          ],

          "outputs": [
            {
              "address": ADDRESS,
              "amount": SATOSHIS
            },
            ...
          ]

        }

    See the file ``examples/signature_requests/bitcoin_testnet.json``
    for a more complete example.

    """

    #
    # Validation
    #

    def validate_request(self) -> None:
        """Validates a signature request

        Validates

        * the witness script
        * inputs & outputs
        * fee
        """
        if self.psbt_obj.validate() is not True:
            raise HermitError("Invalid PSBT")

        self._validate_input_groups()
        self._validate_outputs()
        self._validate_fee()

    def _validate_input_groups(self) -> None:
        if not hasattr(self.psbt_obj, 'psbt_ins'):
            raise InvalidSignatureRequest("no inputs")
        psbt_ins = self.psbt_obj.psbt_ins
        if not isinstance(psbt_ins, list):
            raise InvalidSignatureRequest("psbt_inputs is not an array")
        if len(psbt_ins) == 0:
            raise InvalidSignatureRequest("at least one input in the PSBT is required")
        self.inputs = []
        for psbt_in in psbt_ins:
            self._validate_input_group(psbt_in)

    def _validate_input_group(self, psbt_in: PSBTIn) -> None:
        # TODO: add support for legacy RedeemScript?
        witness_script = psbt_in.witness_script.serialize().hex()
        if witness_script is None:
            raise InvalidSignatureRequest(
                "input group must include witness script"
            )
        self._validate_witness_script(witness_script)
        # Find bip32 path for the key that hermit protects via fingerprint
        bip32_path = None
        root_xfp_hexes = set({})
        for named_pub in psbt_in.named_pubs.values():
            if named_pub.root_fingerprint.hex() == self.wallet.xfp_hex:
                bip32_path = named_pub.root_path
            # not strictly neccesary, using this for a helpful error message below
            root_xfp_hexes.add(named_pub.root_fingerprint.hex())

        if bip32_path is None:
            raise InvalidSignatureRequest(f"BIP32 signing path for fingerprint {self.wallet.xfp_hex} not a fingerprint in this input:\n\t{root_xfp_hexes}")

        self.validate_bip32_path(bip32_path)
        address = generate_multisig_address(witness_script, self.testnet)
        if False:
            # FIXME
            for inp in input_group[2:]:
                self._validate_input(inp)
                inp["witness_script"] = witness_script
                inp["bip32_path"] = bip32_path
                inp["address"] = address
                self.inputs.append(input)

    def _validate_input(self, input: Dict) -> None:
        if "amount" not in input:
            raise InvalidSignatureRequest("no amount in input")
        if type(input["amount"]) != int:
            err_msg = "input amount must be an integer (satoshis)"
            raise InvalidSignatureRequest(err_msg)
        if input["amount"] <= 0:
            raise InvalidSignatureRequest("invalid input amount")

        if "txid" not in input:
            raise InvalidSignatureRequest("no txid in input")
        if len(input["txid"]) != 64:
            raise InvalidSignatureRequest("txid must be 64 characters")
        try:
            binascii.unhexlify(input["txid"].encode("utf8"))
        except ValueError:
            err_msg = "input TXIDs must be hexadecimal strings"
            raise InvalidSignatureRequest(err_msg)

        if "index" not in input:
            raise InvalidSignatureRequest("no index in input")
        if type(input["index"]) != int:
            err_msg = "input index must be an integer"
            raise InvalidSignatureRequest(err_msg)
        if input["index"] < 0:
            raise InvalidSignatureRequest("invalid input index")

    def _validate_witness_script(self, witness_script: bytes) -> None:
        try:
            binascii.unhexlify(witness_script.encode("utf8"))
        except (ValueError, AttributeError):
            raise InvalidSignatureRequest("witness script is not valid hex")

    def _validate_outputs(self) -> None:
        if not hasattr(self.psbt_obj, 'psbt_outs'):
            raise InvalidSignatureRequest("no outputs")
        psbt_outs = self.psbt_obj.psbt_outs
        if not isinstance(psbt_outs, list):
            raise InvalidSignatureRequest("outputs is not an array")
        if len(psbt_outs) == 0:
            raise InvalidSignatureRequest("at least one output is required")
        for psbt_out in psbt_outs:
            self._validate_output(psbt_out)

    def _validate_output(self, psbt_out: PSBTOut) -> None:
        if "address" not in output:
            raise InvalidSignatureRequest("no address in output")
        if not isinstance(output["address"], (str,)):
            err_msg = "output addresses must be base58-encoded strings"
            raise InvalidSignatureRequest(err_msg)

        if output["address"][:2] in ("bc", "tb"):
            try:
                bech32.CBech32Data(output["address"])
            except bech32.Bech32Error:
                err_msg = "invalid bech32 output address (check mainnet vs. testnet)"
                raise InvalidSignatureRequest(err_msg)
        else:
            try:
                base58.CBase58Data(output["address"])
            except base58.InvalidBase58Error:
                err_msg = "output addresses must be base58-encoded strings"
                raise InvalidSignatureRequest(err_msg)
            except base58.Base58ChecksumError:
                err_msg = "invalid output address checksum"
                raise InvalidSignatureRequest(err_msg)
        try:
            # FIXME: validate address and handle error
            print("Not validating", (output["address"]))
        except:
            err_msg = "invalid output address (check mainnet vs. testnet)"
            raise InvalidSignatureRequest(err_msg)

        if "amount" not in output:
            raise InvalidSignatureRequest("no amount in output")
        if type(output["amount"]) != int:
            err_msg = "output amount must be an integer (satoshis)"
            raise InvalidSignatureRequest(err_msg)
        if output["amount"] <= 0:
            raise InvalidSignatureRequest("invalid output amount")

    def _validate_fee(self) -> None:
        sum_inputs = sum([input["amount"] for input in self.inputs])
        sum_outputs = sum([output["amount"] for output in self.outputs])
        self.fee = sum_inputs - sum_outputs
        if self.fee < 0:
            raise InvalidSignatureRequest("fee cannot be negative")

    #
    # Display
    #

    def display_request(self) -> None:
        """Displays the transaction to be signed"""
        print_formatted_text(
            HTML(
                """<i>INPUTS:</i>
{}

<i>OUTPUTS:</i>
{}

<i>FEE:</i> {} BTC
""".format(
                    self._formatted_input_groups(),
                    self._formatted_outputs(),
                    self._format_amount(self.fee),
                )
            )
        )

    def _formatted_input_groups(self) -> str:
        bip32_paths = {}
        addresses: Dict = defaultdict(int)
        for input in self.inputs:
            address = input["address"]
            addresses[address] += input["amount"]
            bip32_paths[address] = input["bip32_path"]  # they're all the same

        lines = []
        for address in addresses:
            lines.append(
                "  {}\t{} BTC\tSigning as {}".format(
                    address,
                    self._format_amount(addresses[address]),
                    bip32_paths[address],
                )
            )
        return "\n".join(lines)

    def _formatted_outputs(self) -> str:
        formatted_outputs = [self._format_output(output) for output in self.outputs]
        return "\n".join(formatted_outputs)

    def _format_output(self, output: Dict) -> str:
        return "  {}\t{} BTC".format(
            output["address"], self._format_amount(output["amount"])
        )

    def _format_amount(self, amount) -> str:
        return "%0.8f" % (amount / pow(10, 8))

    #
    # Signing
    #

    def create_signature(self) -> None:
        """Signs a given transaction"""
        # Keys are derived in base.py

        # Construct Inputs
        tx_inputs = []
        parsed_witness_scripts = {}
        for input in self.inputs:
            if input["witness_script"] not in parsed_witness_scripts:
                parsed_witness_scripts[input["witness_script"]] = TxIn
                CScript(x(input["witness_script"]))

            txid = lx(input["txid"])
            vout = input["index"]
            tx_inputs.append(CMutableTxIn(COutPoint(txid, vout)))

        # Construct Outputs
        tx_outputs = []

        for output in self.outputs:
            print("address", output["address"])
            decoded_address = decode_base58(output["address"])
            print("decoded_address", decoded_address)
            output_script = P2SHScriptPubKey(decoded_address).serialize()
            print("output_script", output_script)
            tx_outputs.append(CMutableTxOut(output["amount"], output_script))

        # Construct Transaction
        tx = CTransaction(tx_inputs, tx_outputs)

        # Construct data for each signature (1 per input)
        signature_hashes = []
        keys = {}
        for input_index, input in enumerate(self.inputs):
            witness_script = input["witness_script"]
            bip32_path = input["bip32_path"]

            # Signature Hash
            signature_hashes.append(
                SignatureHash(
                    parsed_witness_scripts[witness_script], tx, input_index, SIGHASH_ALL
                )
            )

            # Only need to generate keys once per unique BIP32 path
            if keys.get(bip32_path) is None:
                keys[bip32_path] = self.generate_child_keys(bip32_path)
                keys[bip32_path]["signing_key"] = ecdsa.SigningKey.from_string(
                    bytes.fromhex(keys[bip32_path]["private_key"]),
                    curve=ecdsa.SECP256k1,
                )

        # Construct signatures (1 per input)
        #
        # WARNING: We do not append the SIGHASH_ALL byte,
        # transaction constructioin should account for that.
        #
        signatures = []
        for input_index, input in enumerate(self.inputs):
            input = self.inputs[input_index]
            signature_hash = signature_hashes[input_index]
            signing_key = keys[input["bip32_path"]]["signing_key"]
            signatures.append(
                signing_key.sign_digest_deterministic(
                    signature_hash, sha256, sigencode=ecdsa.util.sigencode_der_canonize
                ).hex()
            )

        # Assign result
        result = {"signatures": signatures}

        self.signature = result
