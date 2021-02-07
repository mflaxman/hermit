import json
import re
from typing import Optional, Dict

from prompt_toolkit import PromptSession, print_formatted_text, HTML

from buidl import PSBT

import hermit
from hermit.errors import HermitError, InvalidSignatureRequest
from hermit.qrcode import reader, displayer
from hermit.wallet import (
    compressed_private_key_from_bip32,
    compressed_public_key_from_bip32,
    HDWallet,
)


class Signer(object):
    """Abstract class from which to subclass signing classes for specific assets.

    This class implements the basic framework required to receive a
    signature request and return a signature.

    Subclasses should implement the following API methods:

    * ``validate_request``
    * ``display_request``
    * ``create_signature``

    Subclasses will likely require the following API methods to
    validate and extract BIP32 nodes with which to sign transactions.

    * ``validate_bip32_path``
    * ``generate_child_keys``

    """

    BIP32_PATH_REGEX = "^m(/[0-9]+'?)+$"
    BIP32_NODE_MAX_VALUE = 2147483647

    def __init__(self, signing_wallet: HDWallet, session: PromptSession = None, psbt_b64: str = None) -> None:
        self.wallet = signing_wallet
        self.session = session
        self.signature: Optional[Dict] = None
        self.psbt_b64: Optional[str] = psbt_b64

    def sign(self, testnet: bool = False) -> None:
        """Initiate signing.

        Will wait for a signature request, handle validation,
        confirmation, generation, and display of a signature.
        """

        # FIXME: change all _request names (wait_for*, _parse*, validate*, etc) to something sensical
        self.testnet = testnet
        if not self.psbt_b64:
            # Allow passing through signing request as an argument
            self._wait_for_request()
        if self.psbt_b64:
            self._parse_request()
            self.validate_request()
            if self._confirm_create_signature():
                self.create_signature()
                self._show_signature()

    def validate_request(self) -> None:
        """Validate a signature request.

        Concrete subclasses should override this method.

        The contents of the signature request will already be parsed
        from QR code and available as ``self.request``.

        Invalid requests should raise an appropriate error class with
        message.

        The presence in the request of a valid path to a BIP32 node to
        use when signing is already validated.

        """
        pass

    def validate_bip32_path(self, bip32_path: str) -> None:
        """Validate a BIP32 path

        Used by concrete subclasses to validate a BIP32 path in a
        signature request.
        """
        if not isinstance(bip32_path, (str,)):
            raise InvalidSignatureRequest("BIP32 path must be a string")
        if not re.match(self.BIP32_PATH_REGEX, bip32_path):
            err_msg = "invalid BIP32 path formatting"
            raise InvalidSignatureRequest(err_msg)
        nodes = bip32_path.split("/")[1:]
        node_values = [int(x.replace("'", "")) for x in nodes]
        for node_value in node_values:
            if node_value > self.BIP32_NODE_MAX_VALUE:
                err_msg = "invalid BIP32 path"
                raise InvalidSignatureRequest(err_msg)

    def display_request(self) -> None:
        """Display a signature request.

        Concrete subclasses should override this method.

        The contents of the signature request will already be parsed
        from QR code and available as ``self.request``.

        Use ``print_formatted_text`` to display the signature in a way
        that readable on consoles.

        """
        pass

    def create_signature(self) -> None:
        """Create a signature.

        Concrete subclasses should override this method.

        The contents of the signature request will already be parsed
        from QR code and available as ``self.request``.

        The signature data should be saved as ``self.signature``.

        """
        pass

    def generate_child_keys(self, bip32_path: str) -> Dict:
        """Return keys at a given BIP32 path in the current wallet.

        The dictionary returned will contain the following items from
        the HD node at the given BIP32 path:

        * ``xprv`` -- the extended private key
        * ``xpub`` -- the extended public key
        * ``private_key`` -- the private key
        * ``public_key`` -- the public key
        """
        xprv = self.wallet.extended_private_key(bip32_path)
        xpub = self.wallet.extended_public_key(bip32_path)
        return dict(
            xprv=xprv,
            xpub=xpub,
            private_key=compressed_private_key_from_bip32(xprv).hex(),
            public_key=compressed_public_key_from_bip32(xpub).hex(),
        )

    def _wait_for_request(self) -> None:
        self.psbt_b64 = reader.read_qr_code()

    def _parse_request(self) -> None:
        if self.psbt_b64 is None:
            raise HermitError("No PSBT Supplied")

            
        try:
            self.psbt_obj = PSBT.parse_base64(self.psbt_b64, testnet=self.testnet)
        except Exception as e:
            err_msg = "Invalid PSBT: {} ({})".format(
                e, type(e).__name__
            )
            raise HermitError(err_msg)

    def _confirm_create_signature(self) -> bool:
        self.display_request()
        prompt_msg = "Sign the above transaction? [y/N] "

        if self.session is not None:
            response = self.session.prompt(HTML("<b>{}</b>".format(prompt_msg)))
        else:
            response = input(prompt_msg)

        return response.strip().lower().startswith("y")

    def _show_signature(self) -> None:
        name = self._signature_label()
        print_formatted_text(HTML("<i>Signature Data:</i> "))
        print(json.dumps(self.signature, indent=2))
        displayer.display_qr_code(self._serialized_signature(), name=name)

    def _serialized_signature(self) -> str:
        return json.dumps(self.signature)

    def _signature_label(self) -> str:
        return "Signature"
