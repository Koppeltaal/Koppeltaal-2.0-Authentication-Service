from authlib.jose import JsonWebKey, Key
from flask import current_app


class KeyPairService:

    def get_public_key(self) -> Key:
        return JsonWebKey.import_key(current_app.config['OIDC_JWT_PUBLIC_KEY'])

    def get_keypair(self) -> (Key, Key):
        public_key: Key = JsonWebKey.import_key(current_app.config['OIDC_JWT_PUBLIC_KEY'])
        private_key: Key = JsonWebKey.import_key(current_app.config['OIDC_JWT_PRIVATE_KEY'])
        return private_key, public_key


keypair_service = KeyPairService()
